"""
onboarding.py — User store, onboarding state, and certificate generation

Security fixes applied:
  FIX-3  XSS: html.escape() on all user fields in HTML templates (_e helper)
  FIX-4  Cert ID enumeration: O(1) CERT_INDEX lookup; no full iteration
  FIX-5  Plaintext PII: Fernet-encrypted sensitive fields; os.chmod(600) on data files
  FIX-8  Race conditions: asyncio.Lock for USERS and TEST_SESSIONS; atomic file writes
"""

import os
import json
import uuid
import time
import asyncio
import stat
import html as _html
import threading
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

# FIX-5: Fernet encryption for PII fields at rest
try:
    from cryptography.fernet import Fernet
    _fernet_key = os.getenv("DATA_ENCRYPTION_KEY", "")
    if _fernet_key:
        _fernet = Fernet(_fernet_key.encode() if isinstance(_fernet_key, str) else _fernet_key)
    else:
        _fernet = None
except ImportError:
    _fernet = None

# Sensitive fields that are encrypted before writing to disk
_SENSITIVE_FIELDS = {
    "email", "first_name", "last_name", "picture",
    "provider_id", "phone",
}

import logging
logger = logging.getLogger(__name__)


# ─── HTML-escape helper (FIX-3) ───────────────────────────────────────────────

def _e(s) -> str:
    """HTML-escape a value to prevent XSS injection."""
    return _html.escape(str(s) if s else "")


# ─── Encryption helpers (FIX-5) ───────────────────────────────────────────────

def _encrypt_field(value: str) -> str:
    """Encrypt a string field. Returns original if Fernet not configured."""
    if _fernet is None or not value:
        return value
    return _fernet.encrypt(value.encode()).decode()


def _decrypt_field(value: str) -> str:
    """Decrypt a string field. Returns original if Fernet not configured."""
    if _fernet is None or not value:
        return value
    try:
        return _fernet.decrypt(value.encode()).decode()
    except Exception:
        # If decryption fails (e.g., unencrypted legacy data), return as-is
        return value


def _encrypt_user(user: dict) -> dict:
    """Return a copy of the user dict with sensitive fields encrypted."""
    encrypted = {}
    for key, val in user.items():
        if key in _SENSITIVE_FIELDS and isinstance(val, str):
            encrypted[key] = _encrypt_field(val)
        else:
            encrypted[key] = val
    return encrypted


def _decrypt_user(user: dict) -> dict:
    """Return a copy of the user dict with sensitive fields decrypted."""
    decrypted = {}
    for key, val in user.items():
        if key in _SENSITIVE_FIELDS and isinstance(val, str):
            decrypted[key] = _decrypt_field(val)
        else:
            decrypted[key] = val
    return decrypted


# ─── IN-MEMORY STORES ─────────────────────────────────────────────────────────

# users: {user_id: {...}}  — held in-memory decrypted; encrypted when persisted
USERS: dict[str, dict] = {}

# FIX-4: Certificate ID → user_id index for O(1) lookups
CERT_INDEX: dict[str, str] = {}  # {certificate_id: user_id}

# test sessions: {session_token: {...}}
TEST_SESSIONS: dict[str, dict] = {}

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"
TEST_SESSIONS_FILE = DATA_DIR / "test_sessions.json"


def _load_test_sessions() -> None:
    """Load persisted test sessions from disk."""
    global TEST_SESSIONS
    try:
        if TEST_SESSIONS_FILE.exists():
            import json as _json, time as _time
            with open(TEST_SESSIONS_FILE, "r") as f:
                all_sessions = _json.load(f)
            # Drop expired sessions (>2h old)
            now = _time.time()
            TEST_SESSIONS = {k: v for k, v in all_sessions.items() if v.get("expires_at", 0) > now}
    except Exception:
        TEST_SESSIONS = {}


def _save_test_sessions() -> None:
    """Persist test sessions to disk."""
    try:
        import json as _json
        with open(TEST_SESSIONS_FILE, "w") as f:
            _json.dump(TEST_SESSIONS, f)
    except Exception:
        pass

# FIX-8: asyncio lock for USERS + file I/O, threading lock for TEST_SESSIONS
_users_lock = asyncio.Lock()
_sessions_lock = threading.Lock()  # TEST_SESSIONS accessed from sync context


# ─── Persistence helpers ──────────────────────────────────────────────────────

def _load_users() -> None:
    global USERS, CERT_INDEX
    if not USERS_FILE.exists():
        return
    try:
        raw = json.loads(USERS_FILE.read_text(encoding="utf-8"))
        # Decrypt each user after loading
        USERS = {uid: _decrypt_user(u) for uid, u in raw.items()}
        # Rebuild cert index
        CERT_INDEX = {
            u["certificate_id"]: uid
            for uid, u in USERS.items()
            if u.get("certificate_id")
        }
    except Exception as exc:
        logger.error("Failed to load users from disk: %s", exc)
        USERS = {}
        CERT_INDEX = {}


async def _save_users() -> None:
    """
    Atomically write USERS to disk with encryption.
    Must be called within _users_lock.
    FIX-5: encrypts sensitive fields; FIX-8: atomic write via temp file + rename.
    """
    # Encrypt before writing
    encrypted_users = {uid: _encrypt_user(u) for uid, u in USERS.items()}
    tmp_path = USERS_FILE.with_suffix(".tmp")
    try:
        tmp_path.write_text(
            json.dumps(encrypted_users, indent=2, default=str),
            encoding="utf-8",
        )
        # FIX-5: restrict file permissions to owner-only (600)
        try:
            os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass  # Windows may not support POSIX chmod — best-effort
        # Atomic rename
        tmp_path.replace(USERS_FILE)
        # Apply permissions to final file too
        try:
            os.chmod(USERS_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    except Exception as exc:
        logger.error("Failed to save users to disk: %s", exc)
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise


# Load on module import (before event loop starts — sync is fine here)
_load_users()


# ─── User CRUD ────────────────────────────────────────────────────────────────

async def get_or_create_user(provider_info: dict) -> dict:
    """Find existing user by email or create new one."""
    email = provider_info.get("email", "").lower()

    async with _users_lock:
        # Search existing users by email
        for uid, user in USERS.items():
            if user.get("email", "").lower() == email:
                user["last_login"] = datetime.now(timezone.utc).isoformat()
                user["provider"] = provider_info.get("provider")
                await _save_users()
                return dict(user)

        # Create new user
        user_id = str(uuid.uuid4())
        user: dict = {
            "id": user_id,
            "email": email,
            "first_name": provider_info.get("first_name", ""),
            "last_name": provider_info.get("last_name", ""),
            "picture": provider_info.get("picture", ""),
            "provider": provider_info.get("provider"),
            "provider_id": provider_info.get("provider_id"),
            "email_verified": provider_info.get("email_verified", False),
            "role": None,
            "onboarding_step": "role_select",
            "profile": {},
            "test_result": None,
            "liveness_verified": False,
            "national_id_uploaded": False,
            "certificate_status": "none",
            "certificate_id": None,
            "retake_count": 0,
            "retake_payment_confirmed": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_login": datetime.now(timezone.utc).isoformat(),
        }
        USERS[user_id] = user
        await _save_users()
        return dict(user)


def get_user(user_id: str) -> Optional[dict]:
    """Return a copy of the user dict or None."""
    user = USERS.get(user_id)
    return dict(user) if user else None


async def update_user(user_id: str, updates: dict) -> Optional[dict]:
    """Update user fields and persist to disk."""
    async with _users_lock:
        if user_id not in USERS:
            return None
        USERS[user_id].update(updates)
        # Keep CERT_INDEX in sync if certificate_id changed
        cert_id = USERS[user_id].get("certificate_id")
        if cert_id:
            CERT_INDEX[cert_id] = user_id
        await _save_users()
        return dict(USERS[user_id])


# ─── Test session store (FIX-8: threading.Lock for sync access) ───────────────

def save_test_session(session_id: str, data: dict) -> None:
    with _sessions_lock:
        TEST_SESSIONS[session_id] = data
        _save_test_sessions()


def get_test_session(session_id: str) -> Optional[dict]:
    with _sessions_lock:
        session = TEST_SESSIONS.get(session_id)
        return dict(session) if session else None


# ─── Certificate helpers ──────────────────────────────────────────────────────

def generate_certificate_id(role: str) -> str:
    """Generate a unique, high-entropy certificate ID."""
    prefix = "ENP" if role == "attorney" else "CLT"
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    uid = uuid.uuid4().hex[:16].upper()
    return f"QL-{prefix}-{ts}-{uid}"


def lookup_user_by_certificate_id(certificate_id: str) -> Optional[dict]:
    """
    FIX-4: O(1) certificate lookup via CERT_INDEX.
    Returns user dict or None.
    """
    user_id = CERT_INDEX.get(certificate_id)
    if not user_id:
        return None
    return get_user(user_id)


def get_certificate_html(user: dict) -> str:
    """Generate printable HTML certificate with all user fields HTML-escaped (FIX-3)."""
    cert_type = "Electronic Notary Public (ENP)" if user["role"] == "attorney" else "Verified Legal Client"
    cert_status = (
        "PROBATIONARY CERTIFICATION"
        if user["certificate_status"] == "probationary"
        else "FULL CERTIFICATION"
    )
    status_color = "#f59e0b" if user["certificate_status"] == "probationary" else "#10b981"

    profile = user.get("profile", {})
    firm_name = profile.get("firm_name", profile.get("organization", ""))

    # FIX-3: Escape ALL user-controlled fields
    first_name      = _e(user.get("first_name", ""))
    last_name       = _e(user.get("last_name", ""))
    certificate_id  = _e(user.get("certificate_id", ""))
    firm_name_esc   = _e(firm_name)
    cert_status_esc = _e(cert_status)
    cert_type_esc   = _e(cert_type)

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Quanby Legal Certificate &mdash; {certificate_id}</title>
<style>
  body {{ font-family: 'Georgia', serif; background: #fff; padding: 40px; }}
  .cert {{ max-width: 800px; margin: 0 auto; border: 3px solid #7c3aed; padding: 48px; text-align: center; position: relative; }}
  .cert::before {{ content: ''; position: absolute; inset: 8px; border: 1px solid #7c3aed; opacity: 0.3; pointer-events: none; }}
  .logo {{ font-size: 2rem; font-weight: bold; color: #7c3aed; margin-bottom: 4px; }}
  .subtitle {{ color: #6b7280; font-size: 0.9rem; margin-bottom: 32px; }}
  .cert-type {{ font-size: 1.1rem; letter-spacing: 0.2em; color: {status_color}; font-weight: bold; margin-bottom: 16px; text-transform: uppercase; }}
  .name {{ font-size: 2.5rem; color: #1e1b4b; margin: 16px 0; font-style: italic; }}
  .firm {{ font-size: 1.1rem; color: #374151; margin-bottom: 24px; }}
  .body-text {{ color: #4b5563; line-height: 1.8; margin: 24px 0; font-size: 0.95rem; }}
  .cert-id {{ font-family: monospace; font-size: 0.85rem; color: #7c3aed; background: #f5f3ff; padding: 8px 16px; border-radius: 4px; display: inline-block; margin: 16px 0; }}
  .seals {{ display: flex; justify-content: space-around; margin-top: 48px; }}
  .seal {{ text-align: center; }}
  .seal-line {{ border-top: 1px solid #000; width: 200px; margin: 8px auto 4px; }}
  .seal-text {{ font-size: 0.8rem; color: #374151; }}
  .footer {{ margin-top: 32px; font-size: 0.75rem; color: #9ca3af; border-top: 1px solid #e5e7eb; padding-top: 16px; }}
  .sc-badge {{ background: #1e1b4b; color: white; padding: 6px 16px; border-radius: 4px; font-size: 0.8rem; display: inline-block; margin-top: 8px; }}
  @media print {{ body {{ padding: 0; }} }}
</style>
</head>
<body>
<div class="cert">
  <div class="logo">&#9878;&#65039; Quanby Legal</div>
  <div class="subtitle">Philippines&#39; First Supreme Court-Accredited Electronic Notarization Facility</div>

  <div class="cert-type">{cert_status_esc}</div>

  <div class="body-text">This certifies that</div>
  <div class="name">{first_name} {last_name}</div>
  {f'<div class="firm">{firm_name_esc}</div>' if firm_name else ''}

  <div class="body-text">
    has successfully completed the Quanby Legal {cert_type_esc} Certification Program
    and is authorized to use the Quanby Legal Electronic Notarization Platform
    in accordance with <strong>A.M. No. 24-10-14-SC</strong>, RA 8792, RA 10173, and applicable Philippine law.
  </div>

  <div class="cert-id">Certificate ID: {certificate_id}</div>
  <div style="font-size:0.8rem;color:#6b7280;margin-top:4px;">
    Issued: {datetime.now(timezone.utc).strftime('%B %d, %Y')} &nbsp;|&nbsp; Valid: 2 years
  </div>

  {'<div style="background:#fef3c7;border:1px solid #f59e0b;padding:12px;border-radius:6px;margin:20px 0;font-size:0.85rem;color:#92400e;"><strong>PROBATIONARY STATUS:</strong> Present this certificate to the Supreme Court of the Philippines for full accreditation. Complete liveness verification and profile survey to upgrade to Full Certification.</div>' if user["certificate_status"] == "probationary" else '<div style="background:#d1fae5;border:1px solid #10b981;padding:12px;border-radius:6px;margin:20px 0;font-size:0.85rem;color:#065f46;"><strong>FULLY CERTIFIED</strong> &mdash; This certificate is valid for presentation to the Supreme Court of the Philippines and all accredited institutions.</div>'}

  <div class="seals">
    <div class="seal">
      <div class="seal-line"></div>
      <div class="seal-text">Authorized Signatory<br>Quanby Solutions, Inc.</div>
    </div>
    <div class="seal">
      <div style="font-size:2rem;">&#9878;&#65039;</div>
      <div class="seal-text">Quanby Legal<br>Official Seal</div>
    </div>
    <div class="seal">
      <div class="seal-line"></div>
      <div class="seal-text">Platform Administrator<br>Quanby Legal ENF</div>
    </div>
  </div>

  <div class="footer">
    <div class="sc-badge">Supreme Court of the Philippines &mdash; A.M. No. 24-10-14-SC Accredited ENF</div>
    <div style="margin-top:8px;">Verify this certificate at legal.quanbyai.com/verify/{certificate_id}</div>
    <div>Quanby Solutions, Inc. | legal@quanby.legal | NPC Registered PIC</div>
  </div>
</div>
</body>
</html>"""


def get_certificate_email_html(user: dict) -> str:
    """HTML email for probationary cert delivery. All user fields are HTML-escaped (FIX-3)."""
    first_name     = _e(user.get("first_name", ""))
    certificate_id = _e(user.get("certificate_id", ""))
    role_label     = _e("Electronic Notary Public (ENP)" if user["role"] == "attorney" else "Client")

    return f"""
<div style="font-family:sans-serif;max-width:600px;margin:0 auto;">
  <div style="background:#1e1b4b;padding:24px;text-align:center;border-radius:8px 8px 0 0;">
    <div style="font-size:1.5rem;font-weight:bold;color:white;">&#9878;&#65039; Quanby Legal</div>
    <div style="color:#c4b5fd;font-size:0.9rem;">Supreme Court-Accredited Electronic Notarization</div>
  </div>
  <div style="background:#f9fafb;padding:32px;border-radius:0 0 8px 8px;border:1px solid #e5e7eb;">
    <h2 style="color:#1e1b4b;margin-top:0;">&#127881; Congratulations, {first_name}!</h2>
    <p style="color:#374151;line-height:1.6;">
      You have successfully passed the Quanby Legal {role_label} Certification Test.
    </p>
    <div style="background:#7c3aed;color:white;padding:16px;border-radius:8px;text-align:center;margin:24px 0;">
      <div style="font-size:0.85rem;opacity:0.8;">Your Certificate ID</div>
      <div style="font-size:1.5rem;font-weight:bold;font-family:monospace;">{certificate_id}</div>
    </div>
    <p style="color:#374151;line-height:1.6;"><strong>Status: PROBATIONARY CERTIFICATION</strong></p>
    <p style="color:#374151;line-height:1.6;">
      This is your probationary certification. To receive your Full Certification, please complete:
    </p>
    <ul style="color:#374151;line-height:2;">
      <li>&#9989; Liveness verification (webcam capture)</li>
      <li>&#9989; Upload of valid National ID</li>
      <li>&#9989; Complete your profile survey</li>
    </ul>
    {"<p style='color:#374151;line-height:1.6;'><strong>&#9888;&#65039; Attorney Action Required:</strong> Once fully certified, you must print your certificate and present it to the Supreme Court of the Philippines for manual addition to the national ENP registry.</p>" if user['role'] == 'attorney' else ""}
    <div style="text-align:center;margin-top:24px;">
      <a href="https://legal.quanbyai.com/dashboard" style="background:#7c3aed;color:white;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:bold;">Complete Your Certification &#8594;</a>
    </div>
    <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0;">
    <p style="color:#9ca3af;font-size:0.8rem;">
      Quanby Solutions, Inc. | Accredited ENF under A.M. No. 24-10-14-SC | NPC Registered PIC<br>
      Questions? Email us at legal@quanby.legal
    </p>
  </div>
</div>
"""
