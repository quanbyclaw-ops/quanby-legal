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
from typing import Optional, Dict
from datetime import datetime, timezone

from fastapi import HTTPException, Request
import httpx
from dotenv import load_dotenv

load_dotenv()

# ─── ENV CONFIG ───────────────────────────────────────────────────────────────
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
FACEBOOK_APP_ID      = os.getenv("FACEBOOK_APP_ID", "")
FACEBOOK_APP_SECRET  = os.getenv("FACEBOOK_APP_SECRET", "")
LINKEDIN_CLIENT_ID   = os.getenv("LINKEDIN_CLIENT_ID", "")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET", "")
JWT_SECRET           = os.getenv("JWT_SECRET", "quanby-legal-jwt-secret-change-in-prod")
FRONTEND_URL         = os.getenv("FRONTEND_URL", "https://legal.quanbyai.com")
APP_URL              = os.getenv("APP_URL", "https://legal.quanbyai.com")

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
    payload["exp"] = int(time.time()) + expires_in
    payload["iat"] = int(time.time())
    body = _b64url(json.dumps(payload).encode())
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
    except Exception:
        return None

# ─── OAUTH HELPERS ────────────────────────────────────────────────────────────

async def google_get_user_info(code: str, redirect_uri: str) -> dict:
    """Exchange Google auth code for user info."""
    async with httpx.AsyncClient() as client:
        # Exchange code for tokens
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
        
        # Get user info
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
            "picture": info.get("picture", {}).get("data", {}).get("url", "") if isinstance(info.get("picture"), dict) else "",
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
        
        # LinkedIn v2 API
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
    """Return OAuth login URLs for all providers."""
    google_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={APP_URL}/api/auth/callback/google"
        f"&response_type=code"
        f"&scope=openid email profile"
        f"&access_type=offline"
    ) if GOOGLE_CLIENT_ID else None
    
    facebook_url = (
        f"https://www.facebook.com/v18.0/dialog/oauth"
        f"?client_id={FACEBOOK_APP_ID}"
        f"&redirect_uri={APP_URL}/api/auth/callback/facebook"
        f"&scope=email,public_profile"
    ) if FACEBOOK_APP_ID else None
    
    linkedin_url = (
        f"https://www.linkedin.com/oauth/v2/authorization"
        f"?response_type=code"
        f"&client_id={LINKEDIN_CLIENT_ID}"
        f"&redirect_uri={APP_URL}/api/auth/callback/linkedin"
        f"&scope=openid profile email"
    ) if LINKEDIN_CLIENT_ID else None
    
    return {
        "google": google_url,
        "facebook": facebook_url,
        "linkedin": linkedin_url,
    }
