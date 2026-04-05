"""
main.py — Quanby Legal Backend
FastAPI application: Contract AI + SSO Auth + Onboarding + Certification

Security fixes applied:
  FIX-1  JWT delivered via HttpOnly Secure cookie, NOT URL query param
  FIX-2  OAuth CSRF: state validated on every callback
  FIX-4  Cert verification uses O(1) CERT_INDEX + rate limiting
  FIX-6  Test retake blocking: retake_count >= 3 returns 403 until payment confirmed
  FIX-7  CORS: restricted to FRONTEND_URL env var (not "*")
  FIX-8  update_user / get_or_create_user are async — awaited correctly
  FIX-10 File upload: os.path.basename() sanitization on all filenames
  FIX-11 JWT: refresh token endpoint; tokens via HttpOnly Secure cookie
  FIX-12 /api/health: no sensitive config details exposed
"""

import os
import json
import time
import uuid
import stat
import base64
from typing import Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Form, Header, Request, Cookie, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from contract_parser import extract_text, clean_text, get_contract_summary_for_context
from ai_engine import analyze_contract, chat_about_contract, generate_contract
from auth import (
    create_jwt, create_access_token, create_refresh_token,
    verify_jwt, verify_refresh_token,
    get_oauth_urls, validate_oauth_state,
    google_get_user_info, facebook_get_user_info, linkedin_get_user_info,
    APP_URL, FRONTEND_URL,
)
from onboarding import (
    get_or_create_user, get_user, update_user,
    save_test_session, get_test_session,
    generate_certificate_id, get_certificate_html, get_certificate_email_html,
    lookup_user_by_certificate_id,
)
from question_bank import get_randomized_test, grade_test

load_dotenv()

# ─── Rate limiter (FIX-4) ────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Quanby Legal",
    description="Supreme Court-Accredited Electronic Notarization Platform",
    version="2.0.0",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─── FIX-7: CORS — restrict to FRONTEND_URL, not "*" ────────────────────────
_allowed_origins_raw = os.getenv("FRONTEND_URL", "https://legal.quanbyai.com")
# Support comma-separated list of origins
_allowed_origins = [o.strip() for o in _allowed_origins_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory contract session store (production: Redis)
sessions: dict = {}

# ─── Cookie settings ──────────────────────────────────────────────────────────
_COOKIE_SECURE   = os.getenv("COOKIE_SECURE", "true").lower() != "false"
_COOKIE_SAMESITE = "lax"
_ACCESS_COOKIE   = "ql_access"
_REFRESH_COOKIE  = "ql_refresh"


def _set_auth_cookies(response: Response, user_id: str, email: str) -> None:
    """FIX-1/11: Set JWT tokens as HttpOnly Secure cookies (never in URL)."""
    access_token  = create_access_token({"user_id": user_id, "email": email})
    refresh_token = create_refresh_token(user_id)

    response.set_cookie(
        key=_ACCESS_COOKIE,
        value=access_token,
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite=_COOKIE_SAMESITE,
        max_age=15 * 60,         # 15 minutes
        path="/",
    )
    response.set_cookie(
        key=_REFRESH_COOKIE,
        value=refresh_token,
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite=_COOKIE_SAMESITE,
        max_age=7 * 24 * 3600,  # 7 days
        path="/api/auth/refresh",
    )


# ─── Models ───────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    session_id: str
    message: str


class GenerateRequest(BaseModel):
    template_type: str
    parameters: dict = {}


class RoleSelectRequest(BaseModel):
    role: str  # "attorney" or "client"


class ProfileRequest(BaseModel):
    first_name: str
    last_name: str
    phone: str
    role: str
    # Attorney fields
    firm_name: Optional[str] = None
    ibp_number: Optional[str] = None
    ptc_number: Optional[str] = None
    legal_address: Optional[str] = None
    num_employees: Optional[str] = None
    mayors_permit: Optional[str] = None
    bir_number: Optional[str] = None
    # Client fields
    organization: Optional[str] = None
    position: Optional[str] = None


class TestAnswerRequest(BaseModel):
    test_session_id: str
    answers: dict  # {question_id: answer_letter}


class RetakePaymentRequest(BaseModel):
    user_id: str
    payment_method: str  # "gcash" or "bank_transfer"


# ─── Auth helpers ─────────────────────────────────────────────────────────────

def _token_from_request(
    authorization: Optional[str],
    ql_access: Optional[str],
) -> Optional[str]:
    """
    FIX-1: Accept token from HttpOnly cookie (primary) or Authorization header (fallback).
    Never accept from query parameters.
    """
    if ql_access:
        return ql_access
    if authorization and authorization.startswith("Bearer "):
        return authorization.split(" ", 1)[1]
    return None


def get_current_user(
    authorization: Optional[str] = None,
    ql_access: Optional[str] = None,
) -> Optional[dict]:
    """Extract user from cookie or Bearer token."""
    token = _token_from_request(authorization, ql_access)
    if not token:
        return None
    payload = verify_jwt(token)
    if not payload:
        return None
    return get_user(payload.get("user_id", ""))


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    """
    Health check endpoint.
    FIX-12: No sensitive config details (API key presence, key names, etc.).
    """
    return {
        "status": "ok",
        "service": "Quanby Legal Contract AI Agent",
        "version": "2.0.0",
        "timestamp": int(time.time()),
    }


@app.post("/api/analyze")
async def analyze_endpoint(
    file: UploadFile = File(...),
    session_id: str = Form(default="default"),
):
    """Upload a PDF/DOCX contract and get AI analysis."""
    # FIX-10: Sanitize filename — strip path traversal
    raw_name = file.filename or "contract"
    filename = os.path.basename(raw_name).replace("..", "").strip() or "contract"

    if not any(filename.lower().endswith(ext) for ext in [".pdf", ".docx", ".doc", ".txt"]):
        raise HTTPException(400, "Unsupported file type. Please upload PDF, DOCX, or TXT files.")

    file_bytes = await file.read()
    if len(file_bytes) > 20 * 1024 * 1024:
        raise HTTPException(400, "File too large. Maximum 20MB.")
    if len(file_bytes) == 0:
        raise HTTPException(400, "Empty file uploaded.")

    try:
        raw_text = extract_text(file_bytes, filename)
        contract_text = clean_text(raw_text)
    except ValueError as e:
        raise HTTPException(422, str(e))

    if len(contract_text.strip()) < 50:
        raise HTTPException(
            422,
            "Could not extract sufficient text from the document. "
            "Please ensure the file is not scanned/image-only.",
        )

    context_text = get_contract_summary_for_context(contract_text, max_length=12000)
    result = analyze_contract(context_text, filename)

    sessions[session_id] = {
        "contract_text": context_text,
        "filename": filename,
        "history": [],
        "analysis": result.get("analysis", {}),
        "created_at": int(time.time()),
    }

    if not result["success"]:
        raise HTTPException(500, result.get("error", "AI analysis failed"))

    return {
        "success": True,
        "session_id": session_id,
        "filename": filename,
        "text_length": len(contract_text),
        "analysis": result["analysis"],
        "tokens_used": result.get("tokens_used"),
    }


@app.post("/api/chat")
async def chat_endpoint(request: ChatRequest):
    """Chat about an uploaded contract."""
    session = sessions.get(request.session_id)
    if not session:
        raise HTTPException(404, "No contract loaded for this session. Please upload a contract first.")

    result = chat_about_contract(
        contract_text=session["contract_text"],
        conversation_history=session["history"],
        user_message=request.message,
        filename=session["filename"],
    )

    if not result["success"]:
        raise HTTPException(500, result.get("error", "Chat failed"))

    session["history"].append({"role": "user", "content": request.message})
    session["history"].append({"role": "assistant", "content": result["response"]})
    sessions[request.session_id]["history"] = session["history"]

    return {
        "success": True,
        "response": result["response"],
        "tokens_used": result.get("tokens_used"),
    }


@app.post("/api/generate")
async def generate_endpoint(request: GenerateRequest):
    """Generate a contract from a template using AI."""
    valid_templates = [
        "deed_of_sale", "lease_agreement", "employment_contract",
        "service_agreement", "loan_agreement", "partnership_agreement",
        "nda", "memorandum_of_agreement", "joint_venture", "power_of_attorney",
    ]
    if request.template_type not in valid_templates:
        raise HTTPException(400, f"Invalid template type. Choose from: {', '.join(valid_templates)}")

    result = generate_contract(request.template_type, request.parameters)
    if not result["success"]:
        raise HTTPException(500, result.get("error", "Generation failed"))

    return {
        "success": True,
        "contract_type": result["contract_type"],
        "contract_text": result["contract_text"],
        "tokens_used": result.get("tokens_used"),
    }


@app.get("/api/templates")
async def list_templates():
    """List available contract templates."""
    return {
        "templates": [
            {"id": "deed_of_sale", "name": "Deed of Absolute Sale", "icon": "🏡", "category": "Real Estate"},
            {"id": "lease_agreement", "name": "Contract of Lease", "icon": "🏢", "category": "Real Estate"},
            {"id": "employment_contract", "name": "Employment Contract", "icon": "👔", "category": "Labor"},
            {"id": "service_agreement", "name": "Service Agreement", "icon": "🤝", "category": "Business"},
            {"id": "loan_agreement", "name": "Loan Agreement", "icon": "💰", "category": "Finance"},
            {"id": "partnership_agreement", "name": "Partnership Agreement", "icon": "🏛️", "category": "Corporate"},
            {"id": "nda", "name": "Non-Disclosure Agreement", "icon": "🔒", "category": "Corporate"},
            {"id": "memorandum_of_agreement", "name": "Memorandum of Agreement", "icon": "📋", "category": "Business"},
            {"id": "joint_venture", "name": "Joint Venture Agreement", "icon": "🤲", "category": "Corporate"},
            {"id": "power_of_attorney", "name": "Special Power of Attorney", "icon": "⚖️", "category": "Legal"},
        ]
    }


# ═══════════════════════════════════════════════════════════════════════════
# AUTH & ONBOARDING ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

# ─── OAuth URLs ───────────────────────────────────────────────────────────────

@app.get("/api/auth/providers")
async def auth_providers():
    """Return OAuth login URLs with CSRF state tokens."""
    return {"providers": get_oauth_urls()}


# ─── FIX-11: Token refresh endpoint ──────────────────────────────────────────

@app.post("/api/auth/refresh")
async def refresh_token_endpoint(
    response: Response,
    ql_refresh: Optional[str] = Cookie(default=None),
):
    """
    Exchange a valid refresh token cookie for a new access token cookie.
    FIX-11: Refresh token support.
    """
    if not ql_refresh:
        raise HTTPException(401, "No refresh token provided")

    payload = verify_refresh_token(ql_refresh)
    if not payload:
        raise HTTPException(401, "Invalid or expired refresh token")

    user = get_user(payload["user_id"])
    if not user:
        raise HTTPException(401, "User not found")

    # Issue new access token cookie only
    access_token = create_access_token({"user_id": user["id"], "email": user["email"]})
    response.set_cookie(
        key=_ACCESS_COOKIE,
        value=access_token,
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite=_COOKIE_SAMESITE,
        max_age=15 * 60,
        path="/",
    )
    return {"success": True, "message": "Access token refreshed"}


# ─── Google OAuth ─────────────────────────────────────────────────────────────

@app.get("/api/auth/callback/google")
async def google_callback(
    request: Request,
    code: str,
    state: Optional[str] = None,
):
    """Handle Google OAuth callback. FIX-2: validate state."""
    if not state:
        raise HTTPException(400, "Missing OAuth state parameter")
    entry = validate_oauth_state(state)
    if not entry:
        raise HTTPException(400, "Invalid or expired OAuth state — possible CSRF attempt")

    redirect_uri = f"{APP_URL}/api/auth/callback/google"
    user_info = await google_get_user_info(code, redirect_uri)
    user = await get_or_create_user(user_info)

    # FIX-1: Deliver token via HttpOnly Secure cookie, NOT query param
    response = RedirectResponse(
        url=f"{FRONTEND_URL}/auth-complete?step={user.get('onboarding_step', 'role_select')}",
        status_code=302,
    )
    _set_auth_cookies(response, user["id"], user["email"])
    return response


@app.get("/api/auth/callback/facebook")
async def facebook_callback(
    request: Request,
    code: str,
    state: Optional[str] = None,
):
    """Handle Facebook OAuth callback. FIX-2: validate state."""
    if not state:
        raise HTTPException(400, "Missing OAuth state parameter")
    entry = validate_oauth_state(state)
    if not entry:
        raise HTTPException(400, "Invalid or expired OAuth state — possible CSRF attempt")

    redirect_uri = f"{APP_URL}/api/auth/callback/facebook"
    user_info = await facebook_get_user_info(code, redirect_uri)
    user = await get_or_create_user(user_info)

    response = RedirectResponse(
        url=f"{FRONTEND_URL}/auth-complete?step={user.get('onboarding_step', 'role_select')}",
        status_code=302,
    )
    _set_auth_cookies(response, user["id"], user["email"])
    return response


@app.get("/api/auth/callback/linkedin")
async def linkedin_callback(
    request: Request,
    code: str,
    state: Optional[str] = None,
):
    """Handle LinkedIn OAuth callback. FIX-2: validate state."""
    if not state:
        raise HTTPException(400, "Missing OAuth state parameter")
    entry = validate_oauth_state(state)
    if not entry:
        raise HTTPException(400, "Invalid or expired OAuth state — possible CSRF attempt")

    redirect_uri = f"{APP_URL}/api/auth/callback/linkedin"
    user_info = await linkedin_get_user_info(code, redirect_uri)
    user = await get_or_create_user(user_info)

    response = RedirectResponse(
        url=f"{FRONTEND_URL}/auth-complete?step={user.get('onboarding_step', 'role_select')}",
        status_code=302,
    )
    _set_auth_cookies(response, user["id"], user["email"])
    return response


# ─── Logout ───────────────────────────────────────────────────────────────────

@app.post("/api/auth/logout")
async def logout(response: Response):
    """Clear auth cookies."""
    response.delete_cookie(_ACCESS_COOKIE, path="/")
    response.delete_cookie(_REFRESH_COOKIE, path="/api/auth/refresh")
    return {"success": True}


# ─── User Session ─────────────────────────────────────────────────────────────

@app.get("/api/auth/me")
async def get_me(
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """Get current user info."""
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")
    return {
        "id": user["id"],
        "email": user["email"],
        "first_name": user["first_name"],
        "last_name": user["last_name"],
        "picture": user.get("picture", ""),
        "role": user.get("role"),
        "onboarding_step": user.get("onboarding_step", "role_select"),
        "certificate_status": user.get("certificate_status", "none"),
        "certificate_id": user.get("certificate_id"),
        "liveness_verified": user.get("liveness_verified", False),
        "national_id_uploaded": user.get("national_id_uploaded", False),
    }


# ─── Onboarding Step 1: Role Selection ───────────────────────────────────────

@app.post("/api/onboarding/role")
async def set_role(
    req: RoleSelectRequest,
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """Set user role: attorney or client."""
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")
    if req.role not in ("attorney", "client"):
        raise HTTPException(400, "Role must be 'attorney' or 'client'")

    await update_user(user["id"], {"role": req.role, "onboarding_step": "profile"})
    return {"success": True, "next_step": "profile"}


# ─── Onboarding Step 2: Profile ───────────────────────────────────────────────

@app.post("/api/onboarding/profile")
async def save_profile(
    req: ProfileRequest,
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """Save user profile information."""
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")

    profile: dict = {
        "first_name": req.first_name,
        "last_name": req.last_name,
        "phone": req.phone,
    }

    if req.role == "attorney":
        profile.update({
            "firm_name": req.firm_name or "",
            "ibp_number": req.ibp_number or "",
            "ptc_number": req.ptc_number or "",
            "legal_address": req.legal_address or "",
            "num_employees": req.num_employees or "",
            "mayors_permit": req.mayors_permit or "",
            "bir_number": req.bir_number or "",
        })
    else:
        profile.update({
            "organization": req.organization or "",
            "position": req.position or "",
            "bir_number": req.bir_number or "",
        })

    await update_user(user["id"], {
        "profile": profile,
        "first_name": req.first_name,
        "last_name": req.last_name,
        "onboarding_step": "test",
    })
    return {"success": True, "next_step": "test"}


# ─── Onboarding Step 3: Certification Test ───────────────────────────────────

_MAX_FREE_RETAKES = 3  # FIX-6


@app.get("/api/certification/start")
async def start_test(
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """
    Start a new randomized certification test.
    FIX-6: Block if retake_count >= MAX_FREE_RETAKES and payment not confirmed.
    """
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")
    if not user.get("role"):
        raise HTTPException(400, "Complete role selection first")

    # FIX-6: Retake enforcement
    retake_count = user.get("retake_count", 0)
    if retake_count >= _MAX_FREE_RETAKES:
        payment_confirmed = user.get("retake_payment_confirmed", False)
        if not payment_confirmed:
            raise HTTPException(
                403,
                {
                    "error": "retake_limit_reached",
                    "message": (
                        f"You have used all {_MAX_FREE_RETAKES} free attempts. "
                        "Please pay the ₱500 retake fee to continue."
                    ),
                    "retake_count": retake_count,
                    "payment_required": True,
                },
            )
        # Payment confirmed — consume it and allow one more attempt
        await update_user(user["id"], {"retake_payment_confirmed": False})

    # Generate randomized test (returns (client_questions, answer_key))
    client_questions, answer_key = get_randomized_test(role=user["role"], count=15)
    test_session_id = str(uuid.uuid4())

    # Store answer key server-side — never sent to client
    save_test_session(test_session_id, {
        "user_id": user["id"],
        "questions": client_questions,
        "answer_key": answer_key,
        "started_at": time.time(),
        "expires_at": time.time() + 3600,
    })

    return {
        "success": True,
        "test_session_id": test_session_id,
        "questions": client_questions,
        "total": 15,
        "passing_score": 80,
        "time_limit_minutes": 60,
        "role": user["role"],
    }


@app.post("/api/certification/submit")
async def submit_test(
    req: TestAnswerRequest,
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """Submit test answers for grading."""
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")

    session = get_test_session(req.test_session_id)
    if not session:
        raise HTTPException(404, "Test session not found or expired")
    if session["user_id"] != user["id"]:
        raise HTTPException(403, "Forbidden")
    if time.time() > session["expires_at"]:
        raise HTTPException(400, "Test session has expired")

    # Grade using server-side answer key
    result = grade_test(
        questions_without_answers=session["questions"],
        answer_key=session["answer_key"],
        user_answers=req.answers,
    )

    retake_count = user.get("retake_count", 0)
    updates: dict = {
        "test_result": result,
        "retake_count": retake_count if result["passed"] else retake_count + 1,
    }

    if result["passed"]:
        cert_id = generate_certificate_id(user.get("role", "client"))
        updates.update({
            "certificate_id": cert_id,
            "certificate_status": "probationary",
            "onboarding_step": "liveness",
        })

    await update_user(user["id"], updates)

    response: dict = {
        "success": True,
        "passed": result["passed"],
        "score": result["score_pct"],
        "correct": result["correct"],
        "total": result["total"],
        "passing_score": result["passing_score"],
    }

    if result["passed"]:
        response.update({
            "certificate_id": updates["certificate_id"],
            "message": "🎉 Congratulations! You passed. Your probationary certificate has been issued.",
            "next_step": "liveness",
        })
    else:
        new_retake_count = updates["retake_count"]
        remaining = max(0, _MAX_FREE_RETAKES - new_retake_count)
        response.update({
            "retake_fee_php": 500,
            "retake_count": new_retake_count,
            "retakes_remaining": remaining,
            "payment_required": remaining == 0,
            "message": (
                f"You scored {result['score_pct']}%. The passing score is 80% (12/15). "
                + (f"{remaining} free attempt(s) remaining." if remaining > 0 else "No free attempts left — ₱500 retake fee required.")
            ),
            "payment_options": ["gcash", "bank_transfer"],
            "gcash_number": os.getenv("GCASH_NUMBER", "09XXXXXXXXX"),
            "bank_name": os.getenv("BANK_NAME", "BDO"),
            "bank_account": os.getenv("BANK_ACCOUNT", "XXXX-XXXX-XXXX"),
            "bank_account_name": os.getenv("BANK_ACCOUNT_NAME", "Quanby Solutions, Inc."),
        })

    return response


# ─── Onboarding Step 4: Liveness + National ID ───────────────────────────────

_ALLOWED_IMAGE_TYPES = {".jpg", ".jpeg", ".png", ".webp"}


def _safe_upload_ext(filename: Optional[str], default: str = "jpg") -> str:
    """FIX-10: Sanitize upload filename — return safe extension only."""
    if not filename:
        return default
    name = os.path.basename(filename).strip()
    _, ext = os.path.splitext(name)
    ext = ext.lower().lstrip(".")
    if ext not in {"jpg", "jpeg", "png", "webp", "pdf"}:
        return default
    return ext


@app.post("/api/onboarding/liveness")
async def submit_liveness(
    selfie: UploadFile = File(...),
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """Submit webcam selfie for liveness verification."""
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")

    selfie_bytes = await selfie.read()
    if len(selfie_bytes) < 1000:
        raise HTTPException(400, "Invalid image — file too small")

    # FIX-10: Sanitize filename
    ext = _safe_upload_ext(selfie.filename)
    selfie_dir = os.path.join(os.path.dirname(__file__), "data", "selfies")
    os.makedirs(selfie_dir, exist_ok=True)
    selfie_path = os.path.join(selfie_dir, f"{user['id']}.{ext}")
    with open(selfie_path, "wb") as f:
        f.write(selfie_bytes)
    # FIX-5: Restrict file permissions
    try:
        os.chmod(selfie_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

    await update_user(user["id"], {"liveness_verified": True})

    updated = get_user(user["id"])
    if updated and updated.get("national_id_uploaded"):
        await update_user(user["id"], {"onboarding_step": "survey"})
        return {"success": True, "message": "Liveness verified ✅", "next_step": "survey"}

    return {"success": True, "message": "Liveness verified ✅", "next_step": "national_id"}


@app.post("/api/onboarding/national-id")
async def upload_national_id(
    national_id: UploadFile = File(...),
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """Upload national ID document."""
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")

    id_bytes = await national_id.read()
    if len(id_bytes) < 1000:
        raise HTTPException(400, "Invalid file")

    # FIX-10: Sanitize filename
    ext = _safe_upload_ext(national_id.filename, default="jpg")
    id_dir = os.path.join(os.path.dirname(__file__), "data", "national_ids")
    os.makedirs(id_dir, exist_ok=True)
    id_path = os.path.join(id_dir, f"{user['id']}.{ext}")
    with open(id_path, "wb") as f:
        f.write(id_bytes)
    # FIX-5: Restrict file permissions
    try:
        os.chmod(id_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

    await update_user(user["id"], {"national_id_uploaded": True})

    updated = get_user(user["id"])
    if updated and updated.get("liveness_verified"):
        await update_user(user["id"], {"onboarding_step": "survey"})
        return {"success": True, "message": "National ID uploaded ✅", "next_step": "survey"}

    return {"success": True, "message": "National ID uploaded ✅", "next_step": "liveness"}


# ─── Onboarding Step 5: Full Certification ───────────────────────────────────

@app.post("/api/onboarding/complete")
async def complete_onboarding(
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """Mark onboarding complete → upgrade cert to fully certified."""
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")

    if not user.get("liveness_verified"):
        raise HTTPException(400, "Liveness verification required")
    if not user.get("national_id_uploaded"):
        raise HTTPException(400, "National ID upload required")
    if not (user.get("test_result") or {}).get("passed"):
        raise HTTPException(400, "Certification test must be passed first")

    await update_user(user["id"], {
        "certificate_status": "certified",
        "onboarding_step": "certified",
    })

    return {
        "success": True,
        "certificate_id": user["certificate_id"],
        "message": "🎉 Full certification complete! Download your certificate and present it to the Supreme Court.",
        "next_step": "certified",
    }


# ─── Certificate Download ─────────────────────────────────────────────────────

@app.get("/api/certificate/{certificate_id}")
async def get_certificate(
    certificate_id: str,
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """Download printable HTML certificate."""
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")
    if user.get("certificate_id") != certificate_id:
        raise HTTPException(403, "Certificate not found for this account")

    html = get_certificate_html(user)
    return HTMLResponse(content=html, status_code=200)


@app.get("/api/verify/{certificate_id}")
@limiter.limit("20/minute")  # FIX-4: Rate limit certificate verification
async def verify_certificate(request: Request, certificate_id: str):
    """
    Public certificate verification endpoint.
    FIX-4: O(1) CERT_INDEX lookup instead of iterating all users.
    """
    user = lookup_user_by_certificate_id(certificate_id)
    if not user:
        return {"valid": False, "certificate_id": certificate_id}

    return {
        "valid": True,
        "certificate_id": certificate_id,
        "name": f"{user.get('first_name', '')} {user.get('last_name', '')}",
        "role": user.get("role"),
        "status": user.get("certificate_status"),
        "issued_at": user.get("created_at"),
    }


# ─── Retake Payment ───────────────────────────────────────────────────────────

@app.post("/api/certification/retake-payment")
async def submit_retake_payment(
    req: RetakePaymentRequest,
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """
    Record retake payment confirmation.
    Production: integrate with PayMongo/GCash webhook before setting confirmed=True.
    """
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")

    # Mark payment as pending — admin/webhook must confirm
    await update_user(user["id"], {"retake_payment_pending": True, "retake_payment_confirmed": False})

    return {
        "success": True,
        "message": f"Payment via {req.payment_method} recorded. Once confirmed by our team, you may retake the test.",
        "instructions": {
            "gcash": f"Send ₱500 to {os.getenv('GCASH_NUMBER', '09XX-XXX-XXXX')} with reference: RETAKE-{user['id'][:8].upper()}",
            "bank_transfer": (
                f"Transfer ₱500 to {os.getenv('BANK_NAME', 'BDO')} "
                f"Acc: {os.getenv('BANK_ACCOUNT', 'XXXX')} | "
                f"Account Name: Quanby Solutions, Inc. | "
                f"Ref: RETAKE-{user['id'][:8].upper()}"
            ),
        },
    }


# ─── Admin: confirm retake payment (protected — add admin auth in production) ─

@app.post("/api/admin/confirm-retake/{user_id}")
async def admin_confirm_retake(
    user_id: str,
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """
    Admin endpoint to confirm a retake payment and unlock next attempt.
    TODO: Add admin-role check before production deployment.
    """
    # Placeholder admin check — replace with proper role-based auth
    admin_secret = os.getenv("ADMIN_SECRET", "")
    token = _token_from_request(authorization, ql_access)
    if not admin_secret or token != admin_secret:
        raise HTTPException(403, "Admin access required")

    target_user = get_user(user_id)
    if not target_user:
        raise HTTPException(404, "User not found")

    await update_user(user_id, {
        "retake_payment_pending": False,
        "retake_payment_confirmed": True,
    })
    return {"success": True, "message": f"Retake unlocked for user {user_id}"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("APP_PORT", 8080))
    uvicorn.run("main:app", host="127.0.0.1", port=port, reload=False)
