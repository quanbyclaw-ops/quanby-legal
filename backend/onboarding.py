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
    """Generate printable HTML certificate - landscape design with orange swoosh accents (FIX-3)."""
    from datetime import datetime, timezone

    profile = user.get("profile", {})
    firm_name = profile.get("firm_name", profile.get("organization", ""))

    # FIX-3: Escape ALL user-controlled fields
    first_name     = _e(user.get("first_name", ""))
    last_name      = _e(user.get("last_name", ""))
    certificate_id = _e(user.get("certificate_id", ""))
    firm_name_esc  = _e(firm_name)
    role           = user.get("role", "attorney")
    cert_status    = user.get("certificate_status", "probationary")

    course_title   = "Electronic Notary Public (ENP) Certification Program"
    issued_date    = datetime.now(timezone.utc).strftime("%B %d, %Y")
    status_label   = "PROBATIONARY" if cert_status == "probationary" else "FULL CERTIFICATION"
    role_label     = "ENP Authorized Attorney" if role == "attorney" else "Verified Legal Client"

    logo_b64 = "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"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Quanby Legal Certificate &mdash; {certificate_id}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700;800;900&family=Open+Sans:wght@400;600&display=swap');
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  html, body {{ width: 297mm; height: 210mm; background: #fff; }}
  body {{ font-family: 'Open Sans', sans-serif; }}
  .cert-page {{
    width: 297mm; height: 210mm;
    background: #fff;
    position: relative;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 0;
  }}

  /* === ORANGE SWOOSH DECORATIONS === */
  .swoosh-top-right {{
    position: absolute;
    top: 0; right: 0;
    width: 160px; height: 210mm;
    z-index: 0;
  }}
  .swoosh-bottom-left {{
    position: absolute;
    bottom: 0; left: 0;
    width: 120px; height: 210mm;
    z-index: 0;
  }}

  /* === GOLD SEAL === */
  .gold-seal {{
    position: absolute;
    top: 20mm; left: 18mm;
    width: 60px; height: 90px;
    z-index: 5;
  }}
  .medal-circle {{
    width: 60px; height: 60px;
    border-radius: 50%;
    background: radial-gradient(circle at 35% 35%, #ffe066, #c9930a 60%, #8a6100 100%);
    box-shadow: 0 2px 12px rgba(180,120,0,0.5), inset 0 2px 6px rgba(255,240,120,0.5);
    border: 3px solid #e6a800;
    position: relative;
    display: flex; align-items: center; justify-content: center;
  }}
  .medal-circle::after {{
    content: '';
    width: 46px; height: 46px;
    border-radius: 50%;
    border: 2px solid rgba(255,220,60,0.7);
    position: absolute;
  }}
  .medal-star {{
    font-size: 1.4rem;
    z-index: 1;
  }}
  .ribbon-top {{
    width: 0; height: 0;
    border-left: 13px solid transparent;
    border-right: 13px solid transparent;
    border-top: 30px solid #e6a800;
    margin: 0 auto;
    position: relative;
    top: -2px;
  }}
  .ribbon-legs {{
    display: flex; justify-content: center; gap: 6px;
    margin-top: -2px;
  }}
  .ribbon-leg {{
    width: 0; height: 0;
    border-left: 8px solid transparent;
    border-right: 8px solid transparent;
    border-top: 20px solid #c9930a;
  }}
  .ribbon-leg.right {{ border-top-color: #a87000; }}

  /* === MAIN CONTENT === */
  .content {{
    position: relative;
    z-index: 10;
    width: 100%;
    padding: 6mm 20mm 0 20mm;
    display: flex;
    flex-direction: column;
    align-items: center;
  }}

  /* HEADER */
  .header-row {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 2mm;
    align-self: center;
  }}
  .logo-img {{ height: 38px; }}
  .org-name {{
    font-family: 'Montserrat', sans-serif;
    font-size: 14pt;
    font-weight: 800;
    color: #1a1a2e;
    letter-spacing: 0.05em;
  }}
  .divider-line {{
    width: 60%; height: 1px;
    background: linear-gradient(90deg, transparent, #e0a800, transparent);
    margin: 2mm auto;
  }}

  /* TITLE */
  .cert-title {{
    font-family: 'Montserrat', sans-serif;
    font-size: 38pt;
    font-weight: 900;
    color: #1a1a1a;
    letter-spacing: 0.04em;
    line-height: 1;
    text-align: center;
    text-transform: uppercase;
    margin-top: 1mm;
  }}
  .cert-subtitle {{
    font-family: 'Montserrat', sans-serif;
    font-size: 16pt;
    font-weight: 700;
    color: #1a1a1a;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    text-align: center;
    margin-top: 1mm;
  }}
  .awarded-to {{
    font-size: 9pt;
    color: #555;
    margin: 3mm 0 1mm;
    font-style: italic;
    text-align: center;
  }}

  /* RECIPIENT */
  .recipient-name {{
    font-family: 'Montserrat', sans-serif;
    font-size: 26pt;
    font-weight: 800;
    color: #1a1a1a;
    text-align: center;
    margin: 2mm 0 1mm;
  }}
  .completing-text {{
    font-size: 8.5pt;
    color: #555;
    text-align: center;
    margin-bottom: 1mm;
  }}
  .course-name {{
    font-family: 'Montserrat', sans-serif;
    font-size: 13pt;
    font-weight: 700;
    color: #1a1a1a;
    text-align: center;
    margin-bottom: 4mm;
  }}

  /* SIGNATURES */
  .sig-row {{
    display: flex;
    justify-content: space-around;
    align-items: flex-end;
    width: 85%;
    margin: 2mm auto 0;
    padding-top: 2mm;
    border-top: none;
  }}
  .sig-block {{
    text-align: center;
    min-width: 110px;
  }}
  .sig-name {{
    font-family: 'Montserrat', sans-serif;
    font-size: 9pt;
    font-weight: 700;
    color: #e6a800;
    margin-bottom: 1mm;
  }}
  .sig-line {{
    width: 100px;
    height: 1px;
    background: #e6a800;
    margin: 0 auto 1mm;
  }}
  .sig-role {{
    font-size: 7.5pt;
    color: #555;
  }}

  /* FOOTER */
  .cert-footer {{
    position: absolute;
    bottom: 6mm;
    left: 22mm;
    right: 22mm;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    z-index: 10;
  }}
  .cert-meta {{
    font-size: 6.5pt;
    color: #888;
    line-height: 1.5;
  }}
  .verify-text {{
    font-size: 6.5pt;
    color: #888;
    text-align: right;
  }}

  @media print {{
    html, body {{ margin: 0; }}
    .cert-page {{ page-break-after: avoid; }}
  }}
</style>
</head>
<body>
<div class="cert-page">

  <!-- ORANGE SWOOSH TOP RIGHT -->
  <svg class="swoosh-top-right" viewBox="0 0 160 793" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="none">
    <path d="M160,0 L160,793 L80,793 Q200,500 60,250 Q0,100 160,0 Z" fill="#f59e0b" opacity="0.85"/>
    <path d="M160,0 L160,793 L110,793 Q260,480 90,230 Q30,80 160,0 Z" fill="#fff8" opacity="0.4"/>
    <path d="M160,0 L160,200 Q80,350 130,550 L160,793 L140,793 Q100,540 150,340 Q190,150 140,0 Z" fill="#fff" opacity="0.18"/>
  </svg>

  <!-- ORANGE SWOOSH BOTTOM LEFT -->
  <svg class="swoosh-bottom-left" viewBox="0 0 120 793" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="none">
    <path d="M0,793 L0,0 L40,0 Q-80,300 60,540 Q120,680 0,793 Z" fill="#f59e0b" opacity="0.85"/>
    <path d="M0,793 L0,0 L20,0 Q-100,310 50,560 Q100,700 0,793 Z" fill="#fff" opacity="0.18"/>
  </svg>

  <!-- GOLD MEDAL SEAL -->
  <div class="gold-seal">
    <div class="ribbon-top"></div>
    <div class="ribbon-legs">
      <div class="ribbon-leg"></div>
      <div class="ribbon-leg right"></div>
    </div>
    <div class="medal-circle">
      <span class="medal-star">★</span>
    </div>
  </div>

  <!-- MAIN CONTENT -->
  <div class="content">
    <!-- Header -->
    <div class="header-row">
      <img src="data:image/png;base64,{logo_b64}" class="logo-img" alt="Quanby Legal">
      <div class="org-name">QUANBY LEGAL</div>
    </div>
    <div class="divider-line"></div>

    <!-- Title -->
    <div class="cert-title">Certificate</div>
    <div class="cert-subtitle">of Completion</div>

    <div class="awarded-to">This certificate is awarded to</div>

    <!-- Recipient -->
    <div class="recipient-name">{first_name} {last_name}</div>
    {f'<div style="font-size:8pt;color:#666;text-align:center;margin-bottom:1mm;">{firm_name_esc}</div>' if firm_name else ''}
    <div class="completing-text">For successfully completing the course titled</div>
    <div class="course-name">{course_title}</div>

    <!-- Signatures -->
    <div class="sig-row">
      <div class="sig-block">
        <div class="sig-name">&nbsp;</div>
        <div class="sig-line"></div>
        <div class="sig-role">Chief Executive Officer</div>
      </div>
      <div class="sig-block">
        <div class="sig-name">{first_name} {last_name}</div>
        <div class="sig-line"></div>
        <div class="sig-role">{role_label}</div>
      </div>
      <div class="sig-block">
        <div class="sig-name">&nbsp;</div>
        <div class="sig-line"></div>
        <div class="sig-role">SC-Accredited ENF</div>
      </div>
    </div>
  </div>

  <!-- FOOTER -->
  <div class="cert-footer">
    <div class="cert-meta">
      Certificate No: {certificate_id}<br>
      Issued: {issued_date} &nbsp;|&nbsp; Status: {status_label}
    </div>
    <div class="verify-text">
      Verify: legal.quanbyai.com/verify/{certificate_id}<br>
      A.M. No. 24-10-14-SC Accredited
    </div>
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
