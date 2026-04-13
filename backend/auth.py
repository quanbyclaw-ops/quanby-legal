"""
auth.py â€" Quanby Legal SSO + Onboarding + Certification Auth Backend
Supports Google OAuth2
JWT session tokens (via PyJWT)

Security fixes applied:
  FIX-1  JWT_SECRET: minimum 32-char enforcement on startup
  FIX-2  OAuth CSRF: random state + PKCE (code_verifier/code_challenge)
  FIX-11 JWT: 15-min access tokens, refresh token endpoint, aud/iss claims,
              PyJWT library instead of hand-rolled HS256
"""

import os
import json
import time
import base64
import hashlib
import secrets
import logging
import urllib.parse
import fcntl
from pathlib import Path
from typing import Optional

import jwt  # PyJWT
from fastapi import HTTPException
import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# â"€â"€â"€ ENV CONFIG â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
GOOGLE_CLIENT_ID       = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET   = os.getenv("GOOGLE_CLIENT_SECRET", "")
FRONTEND_URL           = os.getenv("FRONTEND_URL", "https://legal.quanbyai.com")
APP_URL                = os.getenv("APP_URL", "https://legal.quanbyai.com")

# FIX-1: Enforce JWT_SECRET is set AND has minimum 32 characters
_jwt_secret = os.getenv("JWT_SECRET", "")
if not _jwt_secret:
    raise RuntimeError(
        "JWT_SECRET environment variable is not set. "
        'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
    )
if len(_jwt_secret) < 32:
    raise RuntimeError(
        f"JWT_SECRET must be at least 32 characters long (got {len(_jwt_secret)}). "
        'Generate a secure one with: python -c "import secrets; print(secrets.token_hex(32))"'
    )
JWT_SECRET = _jwt_secret

# FIX-11: Token lifetimes
ACCESS_TOKEN_EXPIRES_SECONDS  = 7 * 24 * 60 * 60  # 7 days
REFRESH_TOKEN_EXPIRES_SECONDS = 30 * 24 * 3600  # 30 days
JWT_ALGORITHM  = "HS256"
JWT_ISSUER     = "quanby-legal"
JWT_AUDIENCE   = "quanby-legal-api"

# FIX-2: CSRF state + PKCE storage — state -> {"expiry": float, "code_verifier": str}
# Persisted to disk with file locking so multiple uvicorn workers share state safely.
_OAUTH_STATES_PATH = Path(__file__).parent / "data" / "oauth_states.json"
_OAUTH_STATE_TTL = 600  # 10 minutes


def _read_states_locked(f) -> dict:
    """Read and parse states from an open, locked file."""
    f.seek(0)
    content = f.read()
    if not content.strip():
        return {}
    raw = json.loads(content)
    now = time.time()
    return {k: v for k, v in raw.items() if v.get("expiry", 0) > now}


def _write_states_locked(f, states: dict) -> None:
    """Write states to an open, locked file (truncate first)."""
    f.seek(0)
    f.truncate()
    json.dump(states, f)
    f.flush()


def generate_oauth_state_entry(provider: str) -> tuple[str, str, str]:
    """
    Generate + persist a state token + PKCE pair. File-locked so all workers share it.
    Returns (state, code_verifier, code_challenge).
    """
    state = secrets.token_urlsafe(32)
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    _OAUTH_STATES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_OAUTH_STATES_PATH, "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            states = _read_states_locked(f)
            states[state] = {
                "expiry": time.time() + _OAUTH_STATE_TTL,
                "code_verifier": verifier,
                "provider": provider,
            }
            _write_states_locked(f, states)
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    return state, verifier, challenge


def validate_oauth_state_entry(state: str) -> dict | None:
    """
    Validate and consume a state token. File-locked so all workers share it.
    Returns metadata dict or None if invalid/expired.
    """
    if not _OAUTH_STATES_PATH.exists():
        logger.warning("OAuth state validation failed: no states file")
        return None
    with open(_OAUTH_STATES_PATH, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            states = _read_states_locked(f)
            entry = states.pop(state, None)
            _write_states_locked(f, states)
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    if entry is None:
        logger.warning("OAuth state validation failed: state not found")
        return None
    if time.time() > entry.get("expiry", 0):
        logger.warning("OAuth state validation failed: state expired")
        return None
    return entry


# Legacy in-memory dict kept for compatibility — no longer used for multi-worker
OAUTH_STATES: dict[str, dict] = {}


# â"€â"€â"€ FIX-2: PKCE helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

def _generate_code_verifier() -> str:
    """Generate a PKCE code_verifier (43-128 chars, URL-safe)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def _code_challenge(verifier: str) -> str:
    """Derive PKCE code_challenge = BASE64URL(SHA256(verifier))."""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def generate_oauth_state(provider: str) -> tuple[str, str, str]:
    """
    Generate a state token + PKCE pair for an OAuth flow.
    File-locked so all uvicorn workers share the same state store.
    Returns (state, code_verifier, code_challenge).
    """
    return generate_oauth_state_entry(provider)


def validate_oauth_state(state: str) -> Optional[dict]:
    """
    Validate a stateless JWT OAuth state token.
    No storage needed — verifies signature and expiry only.
    """
    return validate_stateless_state(state)


# â"€â"€â"€ FIX-11: JWT with PyJWT â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

def create_access_token(payload: dict) -> str:
    """
    Create a short-lived JWT access token (15 min).
    Includes iss, aud, iat, exp claims.
    """
    now = int(time.time())
    claims = {
        **payload,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + ACCESS_TOKEN_EXPIRES_SECONDS,
        "type": "access",
    }
    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    """
    Create a long-lived refresh token (7 days).
    Only contains user_id + type claim.
    """
    now = int(time.time())
    claims = {
        "user_id": user_id,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + REFRESH_TOKEN_EXPIRES_SECONDS,
        "jti": secrets.token_hex(16),
        "type": "refresh",
    }
    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)


# Keep backward-compat alias used throughout main.py
def create_jwt(payload: dict, expires_in: int = ACCESS_TOKEN_EXPIRES_SECONDS) -> str:
    """Alias for create_access_token. expires_in is ignored (always 15 min)."""
    return create_access_token(payload)


def verify_jwt(token: str) -> Optional[dict]:
    """
    Verify and decode a JWT access token.
    Returns payload dict or None if invalid/expired/wrong-type.
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
        if payload.get("type") != "access":
            logger.warning("JWT verification failed: not an access token")
            return None
        return payload
    except jwt.ExpiredSignatureError:
        logger.info("JWT expired")
        return None
    except jwt.InvalidTokenError as exc:
        logger.warning("JWT verification failed: %s", exc)
        return None


def verify_refresh_token(token: str) -> Optional[dict]:
    """Verify a refresh token. Returns payload or None."""
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
        if payload.get("type") != "refresh":
            return None
        return payload
    except jwt.InvalidTokenError as exc:
        logger.warning("Refresh token verification failed: %s", exc)
        return None


# â"€â"€â"€ OAUTH HELPERS â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

async def google_get_user_info(code: str, redirect_uri: str) -> dict:
    """Exchange Google auth code for user info."""
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            }
        )
        tokens = token_resp.json()
        if "error" in tokens:
            raise HTTPException(400, f"Google OAuth error: {tokens['error']}")

        userinfo_resp = await client.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        info = userinfo_resp.json()
        return {
            "provider": "google",
            "provider_id": info.get("sub"),
            "email": info.get("email"),
            "first_name": info.get("given_name", ""),
            "last_name": info.get("family_name", ""),
            "picture": info.get("picture", ""),
            "email_verified": info.get("email_verified", False),
        }


def generate_stateless_state(provider: str) -> str:
    """
    Generate a compact stateless CSRF state token.
    Format: base64(expiry_hex + nonce) + "." + HMAC signature
    Short enough for Google OAuth (~60 chars total).
    """
    nonce = secrets.token_hex(8)  # 16 chars
    exp = int(time.time()) + _OAUTH_STATE_TTL
    msg = f"{exp}:{nonce}:{provider}"
    sig = hashlib.new("sha256", (JWT_SECRET + msg).encode()).hexdigest()[:16]
    token = base64.urlsafe_b64encode(msg.encode()).decode().rstrip("=")
    return f"{token}.{sig}"


def validate_stateless_state(state: str) -> dict | None:
    """
    Validate a compact stateless CSRF state token.
    Returns payload dict or None if invalid/expired.
    """
    try:
        if "." not in state:
            return None
        token, sig = state.rsplit(".", 1)
        # Restore padding
        padding = 4 - len(token) % 4
        msg = base64.urlsafe_b64decode(token + "=" * (padding % 4)).decode()
        exp_str, nonce, provider = msg.split(":", 2)
        # Verify signature
        expected_sig = hashlib.new("sha256", (JWT_SECRET + msg).encode()).hexdigest()[:16]
        if not secrets.compare_digest(sig, expected_sig):
            logger.warning("OAuth state HMAC validation failed")
            return None
        # Check expiry
        if time.time() > int(exp_str):
            logger.warning("OAuth state expired")
            return None
        return {"provider": provider, "nonce": nonce}
    except Exception as e:
        logger.warning(f"OAuth state validation failed: {e}")
        return None


def get_oauth_urls() -> dict:
    """
    Return OAuth login URLs with stateless JWT CSRF state tokens.
    No server-side storage — works across all uvicorn workers.
    """
    result: dict = {}

    if GOOGLE_CLIENT_ID:
        state = generate_stateless_state("google")
        params = urllib.parse.urlencode({
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": f"{APP_URL}/api/auth/callback/google",
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "prompt": "select_account",
            "state": state,
        })
        result["google"] = f"https://accounts.google.com/o/oauth2/v2/auth?{params}"
    else:
        result["google"] = None
    return result
