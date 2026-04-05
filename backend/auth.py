"""
auth.py — Quanby Legal SSO + Onboarding + Certification Auth Backend
Supports Google, Facebook, LinkedIn OAuth2
JWT session tokens
"""

import os
import json
import time
import uuid
import hmac
import hashlib
import base64
import secrets
import logging
import urllib.parse
from typing import Optional

from fastapi import HTTPException
import httpx
from dotenv import load_dotenv

load_dotenv()

# Fix 5: Logger for JWT verification warnings
logger = logging.getLogger(__name__)

# ─── ENV CONFIG ───────────────────────────────────────────────────────────────
GOOGLE_CLIENT_ID       = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET   = os.getenv("GOOGLE_CLIENT_SECRET", "")
FACEBOOK_APP_ID        = os.getenv("FACEBOOK_APP_ID", "")
FACEBOOK_APP_SECRET    = os.getenv("FACEBOOK_APP_SECRET", "")
LINKEDIN_CLIENT_ID     = os.getenv("LINKEDIN_CLIENT_ID", "")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET", "")
FRONTEND_URL           = os.getenv("FRONTEND_URL", "https://legal.quanbyai.com")
APP_URL                = os.getenv("APP_URL", "https://legal.quanbyai.com")

# Fix 1: Remove hardcoded JWT_SECRET fallback — fail fast if not set
_jwt_secret = os.getenv("JWT_SECRET")
if not _jwt_secret:
    raise RuntimeError(
        "JWT_SECRET environment variable is not set. "
        'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
    )
JWT_SECRET = _jwt_secret

# Fix 2: CSRF state storage — state -> expiry timestamp
OAUTH_STATES: dict[str, float] = {}
_OAUTH_STATE_TTL = 600  # 10 minutes


def generate_oauth_state() -> str:
    """Generate a cryptographically secure OAuth CSRF state token."""
    return secrets.token_urlsafe(32)


def validate_oauth_state(state: str) -> bool:
    """Validate and consume an OAuth state token (one-time use, 10-min TTL)."""
    expiry = OAUTH_STATES.pop(state, None)
    if expiry is None:
        return False
    if time.time() > expiry:
        return False
    return True


# ─── SIMPLE JWT (no external lib needed) ─────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def create_jwt(payload: dict, expires_in: int = 86400 * 7) -> str:
    """Create a signed JWT token (HS256). Valid for 7 days by default."""
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    # Fix 3: Never mutate input payload — work on a copy, add jti for uniqueness
    token_payload = {
        **payload,
        "exp": int(time.time()) + expires_in,
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
    }
    body = _b64url(json.dumps(token_payload).encode())
    sig_input = f"{header}.{body}".encode()
    sig = hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url(sig)}"


def verify_jwt(token: str) -> Optional[dict]:
    """Verify and decode a JWT. Returns None if invalid/expired."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        sig_input = f"{header}.{body}".encode()
        expected_sig = _b64url(hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(_b64url_decode(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception as e:
        # Fix 5: Log JWT verification failures at WARNING level
        logger.warning("JWT verification failed: %s", e)
        return None


# ─── OAUTH HELPERS ────────────────────────────────────────────────────────────

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


async def facebook_get_user_info(code: str, redirect_uri: str) -> dict:
    """Exchange Facebook auth code for user info."""
    async with httpx.AsyncClient() as client:
        token_resp = await client.get(
            "https://graph.facebook.com/v18.0/oauth/access_token",
            params={
                "client_id": FACEBOOK_APP_ID,
                "client_secret": FACEBOOK_APP_SECRET,
                "redirect_uri": redirect_uri,
                "code": code,
            }
        )
        tokens = token_resp.json()
        if "error" in tokens:
            raise HTTPException(400, f"Facebook OAuth error: {tokens['error']}")

        userinfo_resp = await client.get(
            "https://graph.facebook.com/me",
            params={
                "fields": "id,first_name,last_name,email,picture",
                "access_token": tokens["access_token"]
            }
        )
        info = userinfo_resp.json()
        return {
            "provider": "facebook",
            "provider_id": info.get("id"),
            "email": info.get("email", ""),
            "first_name": info.get("first_name", ""),
            "last_name": info.get("family_name", info.get("last_name", "")),
            "picture": (
                info.get("picture", {}).get("data", {}).get("url", "")
                if isinstance(info.get("picture"), dict) else ""
            ),
            "email_verified": True,  # Facebook email is verified
        }


async def linkedin_get_user_info(code: str, redirect_uri: str) -> dict:
    """Exchange LinkedIn auth code for user info."""
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            "https://www.linkedin.com/oauth/v2/accessToken",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": LINKEDIN_CLIENT_ID,
                "client_secret": LINKEDIN_CLIENT_SECRET,
                "redirect_uri": redirect_uri,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        tokens = token_resp.json()
        if "error" in tokens:
            raise HTTPException(400, f"LinkedIn OAuth error: {tokens['error']}")

        profile_resp = await client.get(
            "https://api.linkedin.com/v2/userinfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        info = profile_resp.json()
        return {
            "provider": "linkedin",
            "provider_id": info.get("sub"),
            "email": info.get("email", ""),
            "first_name": info.get("given_name", ""),
            "last_name": info.get("family_name", ""),
            "picture": info.get("picture", ""),
            "email_verified": info.get("email_verified", False),
        }


def get_oauth_urls() -> dict:
    """Return OAuth login URLs with CSRF state tokens for all providers."""
    # Fix 2: Generate state tokens and store with TTL
    # Fix 4: Use urllib.parse.urlencode for all query params

    if GOOGLE_CLIENT_ID:
        google_state = generate_oauth_state()
        OAUTH_STATES[google_state] = time.time() + _OAUTH_STATE_TTL
        google_params = urllib.parse.urlencode({
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": f"{APP_URL}/api/auth/callback/google",
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "state": google_state,
        })
        google_url = f"https://accounts.google.com/o/oauth2/v2/auth?{google_params}"
    else:
        google_url = None
        google_state = None

    if FACEBOOK_APP_ID:
        facebook_state = generate_oauth_state()
        OAUTH_STATES[facebook_state] = time.time() + _OAUTH_STATE_TTL
        facebook_params = urllib.parse.urlencode({
            "client_id": FACEBOOK_APP_ID,
            "redirect_uri": f"{APP_URL}/api/auth/callback/facebook",
            "scope": "email,public_profile",
            "state": facebook_state,
        })
        facebook_url = f"https://www.facebook.com/v18.0/dialog/oauth?{facebook_params}"
    else:
        facebook_url = None
        facebook_state = None

    if LINKEDIN_CLIENT_ID:
        linkedin_state = generate_oauth_state()
        OAUTH_STATES[linkedin_state] = time.time() + _OAUTH_STATE_TTL
        linkedin_params = urllib.parse.urlencode({
            "response_type": "code",
            "client_id": LINKEDIN_CLIENT_ID,
            "redirect_uri": f"{APP_URL}/api/auth/callback/linkedin",
            "scope": "openid profile email",
            "state": linkedin_state,
        })
        linkedin_url = f"https://www.linkedin.com/oauth/v2/authorization?{linkedin_params}"
    else:
        linkedin_url = None
        linkedin_state = None

    return {
        "google": google_url,
        "facebook": facebook_url,
        "linkedin": linkedin_url,
        "states": {
            "google": google_state,
            "facebook": facebook_state,
            "linkedin": linkedin_state,
        },
    }
