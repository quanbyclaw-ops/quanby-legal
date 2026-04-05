"""
auth.py — Quanby Legal SSO + Onboarding + Certification Auth Backend
Supports Google, Facebook, LinkedIn OAuth2
JWT session tokens (via PyJWT)

Security fixes applied:
  FIX-1  JWT_SECRET: minimum 32-char enforcement on startup
  FIX-2  OAuth CSRF: random state + PKCE (code_verifier/code_challenge)
  FIX-11 JWT: 15-min access tokens, refresh token endpoint, aud/iss claims,
              PyJWT library instead of hand-rolled HS256
"""

import os
import time
import base64
import hashlib
import secrets
import logging
import urllib.parse
from typing import Optional

import jwt  # PyJWT
from fastapi import HTTPException
import httpx
from dotenv import load_dotenv

load_dotenv()

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
ACCESS_TOKEN_EXPIRES_SECONDS  = 15 * 60        # 15 minutes
REFRESH_TOKEN_EXPIRES_SECONDS = 7 * 24 * 3600  # 7 days
JWT_ALGORITHM  = "HS256"
JWT_ISSUER     = "quanby-legal"
JWT_AUDIENCE   = "quanby-legal-api"

# FIX-2: CSRF state + PKCE storage — state -> {"expiry": float, "code_verifier": str}
OAUTH_STATES: dict[str, dict] = {}
_OAUTH_STATE_TTL = 600  # 10 minutes


# ─── FIX-2: PKCE helpers ──────────────────────────────────────────────────────

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
    Returns (state, code_verifier, code_challenge).
    State is stored in OAUTH_STATES with TTL.
    """
    state = secrets.token_urlsafe(32)
    verifier = _generate_code_verifier()
    challenge = _code_challenge(verifier)
    OAUTH_STATES[state] = {
        "expiry": time.time() + _OAUTH_STATE_TTL,
        "code_verifier": verifier,
        "provider": provider,
    }
    return state, verifier, challenge


def validate_oauth_state(state: str) -> Optional[dict]:
    """
    Validate and consume an OAuth state token (one-time use).
    Returns the stored metadata dict (including code_verifier) or None if invalid.
    """
    entry = OAUTH_STATES.pop(state, None)
    if entry is None:
        logger.warning("OAuth state validation failed: state not found")
        return None
    if time.time() > entry["expiry"]:
        logger.warning("OAuth state validation failed: state expired")
        return None
    return entry


# ─── FIX-11: JWT with PyJWT ───────────────────────────────────────────────────

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
            "email_verified": True,
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
    """
    Return OAuth login URLs with CSRF state tokens + PKCE for all providers.
    FIX-2: state is unique per provider per call; PKCE code_challenge included.
    """
    result: dict = {}

    if GOOGLE_CLIENT_ID:
        state, _verifier, challenge = generate_oauth_state("google")
        params = urllib.parse.urlencode({
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": f"{APP_URL}/api/auth/callback/google",
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        result["google"] = f"https://accounts.google.com/o/oauth2/v2/auth?{params}"
    else:
        result["google"] = None

    if FACEBOOK_APP_ID:
        state, _verifier, _challenge = generate_oauth_state("facebook")
        # Facebook does not support PKCE for server-side flows; state alone is sufficient
        params = urllib.parse.urlencode({
            "client_id": FACEBOOK_APP_ID,
            "redirect_uri": f"{APP_URL}/api/auth/callback/facebook",
            "scope": "email,public_profile",
            "state": state,
        })
        result["facebook"] = f"https://www.facebook.com/v18.0/dialog/oauth?{params}"
    else:
        result["facebook"] = None

    if LINKEDIN_CLIENT_ID:
        state, _verifier, _challenge = generate_oauth_state("linkedin")
        params = urllib.parse.urlencode({
            "response_type": "code",
            "client_id": LINKEDIN_CLIENT_ID,
            "redirect_uri": f"{APP_URL}/api/auth/callback/linkedin",
            "scope": "openid profile email",
            "state": state,
        })
        result["linkedin"] = f"https://www.linkedin.com/oauth/v2/authorization?{params}"
    else:
        result["linkedin"] = None

    return result
