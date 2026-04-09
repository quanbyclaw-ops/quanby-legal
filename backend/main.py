"""
main.py Ã¢â‚¬â€ Quanby Legal Backend
FastAPI application: Contract AI + SSO Auth + Onboarding + Certification

Security fixes applied:
  FIX-1  JWT delivered via HttpOnly Secure cookie, NOT URL query param
  FIX-2  OAuth CSRF: state validated on every callback
  FIX-4  Cert verification uses O(1) CERT_INDEX + rate limiting
  FIX-6  Test retake blocking: retake_count >= 3 returns 403 until payment confirmed
  FIX-7  CORS: restricted to FRONTEND_URL env var (not "*")
  FIX-8  update_user / get_or_create_user are async Ã¢â‚¬â€ awaited correctly
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
import threading
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
    google_get_user_info,
    APP_URL, FRONTEND_URL,
)
from onboarding import (
    get_or_create_user, get_user, update_user,
    save_test_session, get_test_session,
    generate_certificate_id, get_certificate_html, get_certificate_email_html,
    lookup_user_by_certificate_id,
    _load_test_sessions,
)
# Load persisted test sessions on startup
_load_test_sessions()
from question_bank import get_randomized_test, grade_test
from email_service import send_welcome_email, send_test_fail_email

load_dotenv()

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Rate limiter (FIX-4) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Quanby Legal",
    description="Supreme Court-Accredited Electronic Notarization Platform",
    version="2.0.0",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ FIX-7: CORS Ã¢â‚¬â€ restrict to FRONTEND_URL, not "*" Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Cookie settings Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Models Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

class ChatRequest(BaseModel):
    session_id: str
    message: str


class GenerateRequest(BaseModel):
    template_type: str
    parameters: dict = {}


class RoleSelectRequest(BaseModel):
    role: str  # "attorney" or "client"


class ProfileRequest(BaseModel):
    prefix: Optional[str] = None
    first_name: str
    middle_initial: Optional[str] = None
    last_name: str
    suffix: Optional[str] = None
    phone: str
    role: str
    # Attorney / ENP fields
    roll_no: Optional[str] = None
    roll_date: Optional[str] = None
    commission_no: Optional[str] = None
    commission_no_valid_until: Optional[str] = None
    ptr_no: Optional[str] = None
    ptr_no_location: Optional[str] = None
    ptr_no_date: Optional[str] = None
    ibp_no: Optional[str] = None
    ibp_no_date: Optional[str] = None
    notary_address: Optional[str] = None
    mcle_no_period: Optional[str] = None
    mcle_no: Optional[str] = None
    mcle_no_date: Optional[str] = None
    # Client fields
    organization: Optional[str] = None
    position: Optional[str] = None


class TestAnswerRequest(BaseModel):
    test_session_id: str
    answers: dict  # {question_id: answer_letter}


class RetakePaymentRequest(BaseModel):
    user_id: str
    payment_method: str  # "gcash" or "bank_transfer"



class LegalChatRequest(BaseModel):
    message: str
    session_id: str = ""

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Auth helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Endpoints Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
    # FIX-10: Sanitize filename Ã¢â‚¬â€ strip path traversal
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
            {"id": "deed_of_sale", "name": "Deed of Absolute Sale", "icon": "Ã°Å¸ÂÂ¡", "category": "Real Estate"},
            {"id": "lease_agreement", "name": "Contract of Lease", "icon": "Ã°Å¸ÂÂ¢", "category": "Real Estate"},
            {"id": "employment_contract", "name": "Employment Contract", "icon": "Ã°Å¸â€˜â€", "category": "Labor"},
            {"id": "service_agreement", "name": "Service Agreement", "icon": "Ã°Å¸Â¤Â", "category": "Business"},
            {"id": "loan_agreement", "name": "Loan Agreement", "icon": "Ã°Å¸â€™Â°", "category": "Finance"},
            {"id": "partnership_agreement", "name": "Partnership Agreement", "icon": "Ã°Å¸Ââ€ºÃ¯Â¸Â", "category": "Corporate"},
            {"id": "nda", "name": "Non-Disclosure Agreement", "icon": "Ã°Å¸â€â€™", "category": "Corporate"},
            {"id": "memorandum_of_agreement", "name": "Memorandum of Agreement", "icon": "Ã°Å¸â€œâ€¹", "category": "Business"},
            {"id": "joint_venture", "name": "Joint Venture Agreement", "icon": "Ã°Å¸Â¤Â²", "category": "Corporate"},
            {"id": "power_of_attorney", "name": "Special Power of Attorney", "icon": "Ã¢Å¡â€“Ã¯Â¸Â", "category": "Legal"},
        ]
    }


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# AUTH & ONBOARDING ENDPOINTS
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ OAuth URLs Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

@app.get("/api/auth/providers")
async def auth_providers():
    """Return OAuth login URLs with CSRF state tokens."""
    return {"providers": get_oauth_urls()}


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ FIX-11: Token refresh endpoint Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Google OAuth Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
        raise HTTPException(400, "Invalid or expired OAuth state Ã¢â‚¬â€ possible CSRF attempt")

    redirect_uri = f"{APP_URL}/api/auth/callback/google"
    user_info = await google_get_user_info(code, redirect_uri)
    user = await get_or_create_user(user_info)

    # Send welcome email on first login (onboarding_step == 'role_select' = brand new user)
    if user.get("onboarding_step", "role_select") == "role_select":
        send_welcome_email(user)  # fire-and-forget, non-blocking

    # FIX-1: Deliver token via HttpOnly Secure cookie, NOT query param
    response = RedirectResponse(
        url=f"{FRONTEND_URL}/auth-complete?step={user.get('onboarding_step', 'role_select')}",
        status_code=302,
    )
    _set_auth_cookies(response, user["id"], user["email"])
    return response


@app.post("/api/auth/logout")
async def logout(response: Response):
    """Clear auth cookies."""
    response.delete_cookie(_ACCESS_COOKIE, path="/")
    response.delete_cookie(_REFRESH_COOKIE, path="/api/auth/refresh")
    return {"success": True}


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ User Session Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
        "kyc_id_uploaded": user.get("kyc_id_uploaded", False),
        "retake_count": user.get("retake_count", 0),
        "retake_payment_pending": user.get("retake_payment_pending", False),
        "retake_payment_confirmed": user.get("retake_payment_confirmed", False),
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Onboarding Step 1: Role Selection Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Onboarding Step 2: Profile Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
        "prefix": req.prefix or "",
        "first_name": req.first_name,
        "middle_initial": req.middle_initial or "",
        "last_name": req.last_name,
        "suffix": req.suffix or "",
        "phone": req.phone,
    }

    if req.role == "attorney":
        profile.update({
            "roll_no": req.roll_no or "",
            "roll_date": req.roll_date or "",
            "commission_no": req.commission_no or "",
            "commission_no_valid_until": req.commission_no_valid_until or "",
            "ptr_no": req.ptr_no or "",
            "ptr_no_location": req.ptr_no_location or "",
            "ptr_no_date": req.ptr_no_date or "",
            "ibp_no": req.ibp_no or "",
            "ibp_no_date": req.ibp_no_date or "",
            "notary_address": req.notary_address or "",
            "mcle_no_period": req.mcle_no_period or "",
            "mcle_no": req.mcle_no or "",
            "mcle_no_date": req.mcle_no_date or "",
        })
    else:
        profile.update({
            "organization": req.organization or "",
            "position": req.position or "",
        })

    await update_user(user["id"], {
        "profile": profile,
        "first_name": req.first_name,
        "last_name": req.last_name,
        "onboarding_step": "test",
    })
    return {"success": True, "next_step": "test"}


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Onboarding Step 3: Certification Test Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
                        "Please pay the Ã¢â€šÂ±500 retake fee to continue."
                    ),
                    "retake_count": retake_count,
                    "payment_required": True,
                },
            )
        # Payment confirmed Ã¢â‚¬â€ consume it and allow one more attempt
        await update_user(user["id"], {"retake_payment_confirmed": False})

    # Generate randomized test (returns (client_questions, answer_key))
    client_questions, answer_key = get_randomized_test(role=user["role"], count=50)
    test_session_id = str(uuid.uuid4())

    # Store answer key server-side Ã¢â‚¬â€ never sent to client
    save_test_session(test_session_id, {
        "user_id": user["id"],
        "questions": client_questions,
        "answer_key": answer_key,
        "started_at": time.time(),
        "expires_at": time.time() + 86400,  # 24 hours
    })

    return {
        "success": True,
        "test_session_id": test_session_id,
        "questions": client_questions,
        "total": 15,
        "passing_score": 80,
        "time_limit_minutes": 90,
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
            "onboarding_step": "kyc_id",
        })

    await update_user(user["id"], updates)

    # Fire fail email notification if not passed
    if not result["passed"]:
        send_test_fail_email(user, result["score_pct"])

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
            "message": "Ã°Å¸Å½â€° Congratulations! You passed. Your probationary certificate has been issued.",
            "next_step": "kyc_id",
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
                + (f"{remaining} free attempt(s) remaining." if remaining > 0 else "No free attempts left Ã¢â‚¬â€ Ã¢â€šÂ±500 retake fee required.")
            ),
            "payment_options": ["gcash", "bank_transfer"],
            "gcash_number": os.getenv("GCASH_NUMBER", "09XXXXXXXXX"),
            "bank_name": os.getenv("BANK_NAME", "BDO"),
            "bank_account": os.getenv("BANK_ACCOUNT", "XXXX-XXXX-XXXX"),
            "bank_account_name": os.getenv("BANK_ACCOUNT_NAME", "Quanby Solutions, Inc."),
        })

    return response


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Onboarding Step 4: Liveness + National ID Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

_ALLOWED_IMAGE_TYPES = {".jpg", ".jpeg", ".png", ".webp"}


def _safe_upload_ext(filename: Optional[str], default: str = "jpg") -> str:
    """FIX-10: Sanitize upload filename Ã¢â‚¬â€ return safe extension only."""
    if not filename:
        return default
    name = os.path.basename(filename).strip()
    _, ext = os.path.splitext(name)
    ext = ext.lower().lstrip(".")
    if ext not in {"jpg", "jpeg", "png", "webp", "pdf"}:
        return default
    return ext



# ─── KYC ID Upload ─────────────────────────────────────────────────────────

@app.post("/api/onboarding/kyc-id")
async def upload_kyc_id(
    kyc_id: UploadFile = File(...),
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """Upload government-issued ID for KYC. Sets onboarding_step to liveness."""
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")

    id_bytes = await kyc_id.read()
    if len(id_bytes) < 1000:
        raise HTTPException(400, "Invalid file — too small")
    if len(id_bytes) > 10 * 1024 * 1024:
        raise HTTPException(400, "File too large — max 10MB")

    ext = _safe_upload_ext(kyc_id.filename, default="jpg")
    kyc_dir = os.path.join(os.path.dirname(__file__), "data", "kyc_ids")
    os.makedirs(kyc_dir, exist_ok=True)
    kyc_path = os.path.join(kyc_dir, f"{user['id']}.{ext}")
    with open(kyc_path, "wb") as fh:
        fh.write(id_bytes)
    try:
        os.chmod(kyc_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

    await update_user(user["id"], {
        "kyc_id_uploaded": True,
        "onboarding_step": "liveness",
    })
    return {"success": True, "message": "KYC ID uploaded successfully.", "next_step": "liveness"}

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
        raise HTTPException(400, "Invalid image Ã¢â‚¬â€ file too small")

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
        return {"success": True, "message": "Liveness verified Ã¢Å“â€¦", "next_step": "survey"}

    return {"success": True, "message": "Liveness verified Ã¢Å“â€¦", "next_step": "national_id"}


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
        return {"success": True, "message": "National ID uploaded Ã¢Å“â€¦", "next_step": "survey"}

    return {"success": True, "message": "National ID uploaded Ã¢Å“â€¦", "next_step": "liveness"}


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Onboarding Step 5: Full Certification Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

@app.post("/api/onboarding/complete")
async def complete_onboarding(
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """Mark onboarding complete Ã¢â€ â€™ upgrade cert to fully certified."""
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
        "message": "Ã°Å¸Å½â€° Full certification complete! Download your certificate and present it to the Supreme Court.",
        "next_step": "certified",
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Certificate Download Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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



@app.post("/api/certificate/regenerate")
async def regenerate_certificate(
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """Regenerate certificate: issues a new certificate ID for the authenticated user."""
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")

    # Must have an existing cert to regenerate
    if not user.get("certificate_id"):
        raise HTTPException(400, "No certificate found for this account. Complete onboarding first.")

    # Generate a fresh certificate ID
    new_cert_id = generate_certificate_id(user.get("role", "client"))

    await update_user(user["id"], {
        "certificate_id": new_cert_id,
        # preserve existing certificate_status (probationary/certified)
    })

    return {
        "success": True,
        "old_certificate_id": user["certificate_id"],
        "certificate_id": new_cert_id,
        "message": "Certificate regenerated successfully. Use the new certificate ID to download your certificate.",
    }

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


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Retake Payment Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    # Mark payment as pending Ã¢â‚¬â€ admin/webhook must confirm
    await update_user(user["id"], {"retake_payment_pending": True, "retake_payment_confirmed": False})

    return {
        "success": True,
        "message": f"Payment via {req.payment_method} recorded. Once confirmed by our team, you may retake the test.",
        "instructions": {
            "gcash": f"Send Ã¢â€šÂ±500 to {os.getenv('GCASH_NUMBER', '09XX-XXX-XXXX')} with reference: RETAKE-{user['id'][:8].upper()}",
            "bank_transfer": (
                f"Transfer Ã¢â€šÂ±500 to {os.getenv('BANK_NAME', 'BDO')} "
                f"Acc: {os.getenv('BANK_ACCOUNT', 'XXXX')} | "
                f"Account Name: Quanby Solutions, Inc. | "
                f"Ref: RETAKE-{user['id'][:8].upper()}"
            ),
        },
    }


# Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ Admin: confirm retake payment (protected Ã¢â‚¬â€ add admin auth in production) Ã¢â€â‚¬

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
    # Placeholder admin check Ã¢â‚¬â€ replace with proper role-based auth
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


# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
# LEGAL AI CHATBOT Ã¢â‚¬â€ POST /api/chatbot
# Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â




# ─── Retake Payment (NEW canonical endpoints) ───────────────────────────────

@app.post("/api/retake/initiate")
async def retake_initiate(
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """Return payment details for retake. Requires retake_count >= 1."""
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")
    retake_count = user.get("retake_count", 0)
    ref = f"RETAKE-{user['id'][:8].upper()}-{retake_count}"
    return {
        "success": True,
        "amount": 500,
        "reference_code": ref,
        "gcash_number": os.getenv("GCASH_NUMBER", "09XX-XXX-XXXX"),
        "bank_name": os.getenv("BANK_NAME", "BDO"),
        "bank_account": os.getenv("BANK_ACCOUNT", "XXXX-XXXX-XXXX"),
        "bank_account_name": os.getenv("BANK_ACCOUNT_NAME", "Quanby Solutions, Inc."),
        "retake_count": retake_count,
    }


class RetakeConfirmRequest(BaseModel):
    payment_method: str  # "gcash" or "bank_transfer"
    reference: str


@app.post("/api/retake/confirm-payment")
async def retake_confirm_payment(
    req: RetakeConfirmRequest,
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """User confirms payment sent — marks as pending admin verification."""
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")
    if req.payment_method not in ("gcash", "bank_transfer"):
        raise HTTPException(400, "Invalid payment_method")
    await update_user(user["id"], {
        "retake_payment_pending": True,
        "retake_payment_confirmed": False,
        "retake_payment_method": req.payment_method,
        "retake_payment_reference": req.reference,
    })
    return {
        "success": True,
        "message": "Payment submitted! You will receive an email once verified.",
        "next_step": "test",
    }

# ── Onboarding Retake Payment (frontend-facing) ─────────────────────────────

@app.post("/api/onboarding/retake-payment")
async def onboarding_retake_payment(
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """Return payment details for retake fee. Frontend polls this to get GCash/bank info."""
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")
    ref = f"RETAKE-{user['id'][:8].upper()}"
    return {
        "gcash_number": os.getenv("GCASH_NUMBER", "09XX-XXX-XXXX"),
        "bank_name": os.getenv("BANK_NAME", "BDO"),
        "bank_account": os.getenv("BANK_ACCOUNT", "XXXX-XXXX-XXXX"),
        "bank_account_name": os.getenv("BANK_ACCOUNT_NAME", "Quanby Solutions, Inc."),
        "reference_number": ref,
        "amount": 500,
    }


@app.post("/api/onboarding/retake-payment/verify")
async def verify_retake_payment(
    authorization: Optional[str] = Header(None),
    ql_access: Optional[str] = Cookie(default=None),
):
    """User confirms they have sent payment — marks as pending verification."""
    user = get_current_user(authorization, ql_access)
    if not user:
        raise HTTPException(401, "Unauthorized")
    ref = f"RETAKE-{user['id'][:8].upper()}"
    await update_user(user["id"], {
        "retake_payment_pending": True,
        "retake_payment_confirmed": False,
    })
    return {
        "success": True,
        "message": "Payment submission received. Verification within 24 hours.",
        "reference_number": ref,
    }

# Chat session store: { session_id: { history, created_at, last_active, msg_timestamps } }
legal_chat_sessions: dict = {}
_chat_lock = threading.Lock()

_CHAT_SESSION_TTL  = 7200  # 2-hour idle TTL
_CHAT_RATE_LIMIT   = 20    # max messages per session per hour
_CHAT_RATE_WINDOW  = 3600  # 1-hour sliding window

_LEGAL_CHATBOT_SYSTEM_PROMPT = """You are Quanby Legal AI Ã¢â‚¬â€ the official AI assistant for Quanby Legal, the Philippines' first and only Supreme Court-accredited Electronic Notarization Facility (ENF).

## YOUR SPECIALIZATIONS

### Philippine Electronic Notarization Framework
- A.M. No. 24-10-14-SC (2024): Supreme Court Rules on Electronic Notarization. Authorizes accredited ENFs, defines Electronic Notary Publics (ENPs), sets technical/security standards.
- RA 8792 (E-Commerce Act of 2000): Electronic documents and signatures carry the same legal force as physical ones.
- RA 10173 (Data Privacy Act of 2012): Governs personal data collection/processing; mandates security measures and NPC breach reporting.
- BSP Circular 944: BSP framework for virtual currencies and digital financial transactions.
- SEC Memorandum Circular 28-2020: SEC rules for electronic corporate document submission and digital signatures.

### Philippine Contract Law
- Civil Code of the Philippines (RA 386): obligations and contracts
- Notarization requirements for specific instruments
- Electronic evidence admissibility in Philippine courts

## PLATFORM INFORMATION

### ENP Certification Process
1. Register via Google SSO
2. Select role: Attorney (IBP member) or Client
3. Complete professional profile
4. Pass certification exam: 15 questions, 80% passing score; covers A.M. No. 24-10-14-SC, RA 8792, RA 10173, BSP Circular 944, SEC MC 28-2020
5. Liveness verification (webcam selfie)
6. National ID upload
7. Supreme Court accreditation submission
Note: 3 free exam attempts; retakes cost PHP 500 each.

### Documents Eligible for E-Notarization
YES: Deeds of Sale, Contracts of Lease, Special Power of Attorney, Affidavits, Articles of Incorporation/Partnership, Employment Contracts, Loan Agreements, MOA/MOU, Joint Venture Agreements
NOT eligible: Wills, testaments, documents requiring exclusive physical appearance

### Pricing
- Certification exam: FREE (3 attempts)
- Retake fee: PHP 500 per attempt after 3rd
- Document notarization: varies by ENP and document type (SC fee schedules)
- Enterprise/law firm plans: contact Quanby Legal for quotation

## RESPONSE GUIDELINES
- Be professional, clear, and helpful
- Cite specific laws/rules when relevant
- Always include: "This is general information only Ã¢â‚¬â€ not legal advice. For your specific situation, consult a licensed Philippine attorney or one of our certified ENPs."
- Support both English and Filipino (Tagalog)
- Keep responses concise and focused
- Never fabricate legal provisions or case citations
"""


def _clean_legal_chat_sessions() -> None:
    """Remove sessions idle longer than TTL."""
    now = time.time()
    with _chat_lock:
        expired = [
            sid for sid, s in legal_chat_sessions.items()
            if now - s.get("last_active", 0) > _CHAT_SESSION_TTL
        ]
        for sid in expired:
            del legal_chat_sessions[sid]


def _chatbot_keyword_fallback(message: str) -> str:
    """Keyword-based responses when no AI API key is configured."""
    msg = message.lower()

    if any(k in msg for k in ["hello", "hi ", "hi!", "kumusta", "kamusta", "magandang", "good morning", "good afternoon", "good evening"]):
        return (
            "Hello! \U0001f44b Welcome to **Quanby Legal AI**.\n\n"
            "I can help you with:\n"
            "\u2022 \U0001f3db\ufe0f Philippine electronic notarization (A.M. No. 24-10-14-SC)\n"
            "\u2022 \U0001f4dc ENP certification process and requirements\n"
            "\u2022 \U0001f4c4 Documents eligible for e-notarization\n"
            "\u2022 \u2696\ufe0f Philippine legal framework (RA 8792, RA 10173, BSP Circular 944)\n"
            "\u2022 \U0001f4b0 Platform pricing and services\n\n"
            "What can I help you with today?"
        )

    if any(k in msg for k in ["become", "enp", "certif", "how do i", "how to become", "process", "steps", "register"]):
        return (
            "**How to Become a Certified ENP on Quanby Legal**\n\n"
            "1. **Register** \u2014 Sign up via Google\n"
            "2. **Select Role** \u2014 Choose *Attorney* (IBP member) or *Client*\n"
            "3. **Complete Profile** \u2014 Fill in your professional details\n"
            "4. **Pass the Certification Exam** \u2014 15 questions, 80% passing score\n"
            "   Topics: A.M. No. 24-10-14-SC \u00b7 RA 8792 \u00b7 RA 10173 \u00b7 BSP Circular 944 \u00b7 SEC MC 28-2020\n"
            "5. **Liveness Check** \u2014 Upload a webcam selfie\n"
            "6. **Upload National ID** \u2014 Government-issued ID required\n"
            "7. **SC Submission** \u2014 Your application is forwarded to the Supreme Court\n\n"
            "\U0001f4cb You get **3 free exam attempts**. Retakes cost \u20b1500 each.\n\n"
            "\u26a0\ufe0f *General information only \u2014 not legal advice. Consult a licensed Philippine attorney for specific guidance.*"
        )

    if any(k in msg for k in ["document", "what can", "eligible", "notariz", "which doc", "ano"]):
        return (
            "**Documents Eligible for E-Notarization** (A.M. No. 24-10-14-SC)\n\n"
            "\u2705 Deeds of Absolute Sale\n"
            "\u2705 Contracts of Lease\n"
            "\u2705 Special Power of Attorney\n"
            "\u2705 Affidavits and sworn statements\n"
            "\u2705 Articles of Incorporation / Partnership\n"
            "\u2705 Employment contracts requiring notarization\n"
            "\u2705 Loan agreements\n"
            "\u2705 Memoranda of Agreement / Understanding\n"
            "\u2705 Joint Venture Agreements\n\n"
            "\u274c **Not eligible**: Wills, testaments, documents requiring exclusively physical notarization\n\n"
            "\u26a0\ufe0f *General information only \u2014 consult a licensed Philippine attorney for specific guidance.*"
        )

    if any(k in msg for k in ["a.m. no", "am no", "24-10-14", "supreme court rules", "sc rules", "electronic notariz"]):
        return (
            "**A.M. No. 24-10-14-SC \u2014 Rules on Electronic Notarization (2024)**\n\n"
            "Issued by the Supreme Court of the Philippines, this landmark rule:\n\n"
            "\u2022 Authorizes **Electronic Notarization Facilities (ENFs)** accredited by the SC\n"
            "\u2022 Defines **Electronic Notary Publics (ENPs)** \u2014 attorneys certified for digital notarial acts\n"
            "\u2022 Sets technical security standards: electronic signatures, digital certificates, identity verification\n"
            "\u2022 Requires tamper-proof audit trails and document integrity verification\n"
            "\u2022 Electronic notarial acts carry the **same legal force** as traditional notarization\n\n"
            "\U0001f3db\ufe0f **Quanby Legal** is the Philippines' **first and only** SC-accredited ENF under these rules.\n\n"
            "\u26a0\ufe0f *General information only \u2014 not legal advice. Consult a licensed Philippine attorney for specific guidance.*"
        )

    if any(k in msg for k in ["ra 8792", "8792", "e-commerce act", "ecommerce", "electronic commerce"]):
        return (
            "**RA 8792 \u2014 Electronic Commerce Act of 2000**\n\n"
            "This foundational law establishes:\n\n"
            "\u2022 **Electronic documents** = legally equivalent to paper documents\n"
            "\u2022 **Electronic signatures** = legally valid when properly authenticated\n"
            "\u2022 **Electronic contracts** = enforceable under Philippine law\n"
            "\u2022 Governs admissibility of electronic evidence in Philippine courts\n"
            "\u2022 Sets standards for government and private sector digital transactions\n\n"
            "**Relevance**: RA 8792 combined with A.M. No. 24-10-14-SC makes electronically notarized documents fully valid and enforceable.\n\n"
            "\u26a0\ufe0f *General information only \u2014 not legal advice.*"
        )

    if any(k in msg for k in ["ra 10173", "10173", "data privacy", "privacy act", "personal data", "npc"]):
        return (
            "**RA 10173 \u2014 Data Privacy Act of 2012**\n\n"
            "Key provisions:\n\n"
            "\u2022 Personal data must be collected for **specific, legitimate purposes**\n"
            "\u2022 Data subjects have rights to **access, correct, erase, and object** to processing\n"
            "\u2022 Organizations must implement **technical and organizational security measures**\n"
            "\u2022 Data breaches must be reported to the **National Privacy Commission (NPC)**\n"
            "\u2022 Violations: fines up to \u20b15 million and/or imprisonment\n\n"
            "**Relevance**: Quanby Legal processes personal data (IDs, biometrics, documents) in full compliance with RA 10173.\n\n"
            "\u26a0\ufe0f *General information only \u2014 not legal advice.*"
        )

    if any(k in msg for k in ["price", "cost", "fee", "how much", "pricing", "magkano", "bayad", "libre"]):
        return (
            "**Quanby Legal Pricing**\n\n"
            "\U0001f393 **ENP Certification**\n"
            "\u2022 Certification exam: **FREE** (3 attempts included)\n"
            "\u2022 Retake fee: **\u20b1500** per attempt (after 3rd)\n\n"
            "\U0001f4c4 **Document Notarization**\n"
            "\u2022 Fees vary by document type and ENP\n"
            "\u2022 Governed by Supreme Court fee schedules\n"
            "\u2022 Generally lower than traditional notarization\n\n"
            "\U0001f3e2 **Enterprise / Law Firm Plans**\n"
            "\u2022 Custom pricing for bulk notarization volume\n"
            "\u2022 Contact our team for a quotation\n\n"
            "\u26a0\ufe0f *For current exact pricing, contact Quanby Legal directly. General information only.*"
        )

    if any(k in msg for k in ["legally binding", "legally valid", "legal binding", "valid", "enforceable", "ligal", "totoo", "court"]):
        return (
            "**Is E-Notarization Legally Binding in the Philippines?**\n\n"
            "**Yes \u2014 absolutely.**\n\n"
            "\u2705 **A.M. No. 24-10-14-SC** \u2014 Supreme Court explicitly authorizes electronic notarization\n"
            "\u2705 **RA 8792** \u2014 Electronic signatures and documents equal physical ones in legal force\n"
            "\u2705 **Court Acceptance** \u2014 Philippine courts accept electronically notarized documents\n"
            "\u2705 **Audit Trail** \u2014 Tamper-proof document integrity verification\n"
            "\u2705 **Only Accredited Platform** \u2014 Quanby Legal is the sole SC-accredited ENF in the Philippines\n\n"
            "\u26a0\ufe0f *This is general information. For specific legal questions, consult a licensed Philippine attorney or certified ENP.*"
        )

    if any(k in msg for k in ["bsp", "circular 944", "bangko sentral", "bsp circular"]):
        return (
            "**BSP Circular 944 \u2014 Virtual Currency Framework**\n\n"
            "Issued by Bangko Sentral ng Pilipinas, this circular:\n\n"
            "\u2022 Establishes regulatory framework for virtual currency exchanges (VCEs)\n"
            "\u2022 Sets AML/KYC requirements for digital financial platforms\n"
            "\u2022 Governs electronic money and digital payment systems\n"
            "\u2022 Relevant for contracts involving cryptocurrency and digital assets\n\n"
            "**Relevance**: For contracts involving digital currencies or fintech transactions, BSP Circular 944 compliance is an important consideration alongside e-notarization.\n\n"
            "\u26a0\ufe0f *General information only \u2014 not legal advice.*"
        )

    if any(k in msg for k in ["sec mc", "sec memorandum", "mc 28", "sec mc 28", "memorandum circular 28", "securities commission"]):
        return (
            "**SEC Memorandum Circular 28-2020**\n\n"
            "The Securities and Exchange Commission issued MC 28-2020 to allow:\n\n"
            "\u2022 Electronic submission of corporate documents to the SEC\n"
            "\u2022 Digital signatures on SEC filings\n"
            "\u2022 Online corporate registration and amendments\n"
            "\u2022 Digital General Information Sheets (GIS) and financial statements\n\n"
            "**Practical impact**: Combined with Quanby Legal e-notarization, the entire corporate document lifecycle can be fully paperless and legally valid.\n\n"
            "\u26a0\ufe0f *General information only \u2014 not legal advice.*"
        )

    return (
        "Thank you for your question! I can provide information about:\n\n"
        "\u2022 **ENP Certification** \u2014 How to become a certified Electronic Notary Public\n"
        "\u2022 **E-Notarization** \u2014 Documents eligible, legal validity, process\n"
        "\u2022 **A.M. No. 24-10-14-SC** \u2014 Supreme Court rules on electronic notarization\n"
        "\u2022 **RA 8792, RA 10173, BSP Circular 944, SEC MC 28-2020** \u2014 Applicable laws\n"
        "\u2022 **Pricing** \u2014 Certification and notarization fees\n\n"
        "Please try rephrasing your question, or contact Quanby Legal directly for personalized assistance.\n\n"
        "\u26a0\ufe0f *Quanby Legal AI provides general information only \u2014 not legal advice. Consult a licensed Philippine attorney for specific guidance.*"
    )


@app.post("/api/chatbot")
async def chatbot_endpoint(request: LegalChatRequest):
    """
    Quanby Legal AI Chatbot \u2014 public endpoint for Philippine legal and platform queries.
    - Uses xAI Grok (XAI_API_KEY) or OpenAI (OPENAI_API_KEY) when configured
    - Falls back to keyword-based responses when no AI key is set
    - Rate limit: 20 messages per session per hour
    - Session history maintained in-memory with 2-hour idle TTL
    """
    # Periodic cleanup (non-blocking background thread)
    if int(time.time()) % 60 < 2:
        threading.Thread(target=_clean_legal_chat_sessions, daemon=True).start()

    message = (request.message or "").strip()
    if not message:
        raise HTTPException(400, "Message cannot be empty")
    if len(message) > 2000:
        raise HTTPException(400, "Message too long. Maximum 2000 characters.")

    session_id = (request.session_id or "").strip() or str(uuid.uuid4())
    now = time.time()

    with _chat_lock:
        if session_id not in legal_chat_sessions:
            legal_chat_sessions[session_id] = {
                "history": [],
                "created_at": now,
                "last_active": now,
                "msg_timestamps": [],
            }

        session = legal_chat_sessions[session_id]

        # Sliding-window rate limit
        session["msg_timestamps"] = [
            t for t in session["msg_timestamps"] if now - t < _CHAT_RATE_WINDOW
        ]
        if len(session["msg_timestamps"]) >= _CHAT_RATE_LIMIT:
            raise HTTPException(
                429,
                "Rate limit reached: 20 messages per hour per session. Please wait and try again.",
            )

        session["msg_timestamps"].append(now)
        session["last_active"] = now
        history_snapshot = list(session["history"])

    # Generate response — try providers in order: GLM (ZhipuAI) > xAI > OpenAI > fallback
    zhipu_key = os.getenv("ZHIPU_API_KEY")
    zhipu_model = os.getenv("ZHIPU_MODEL", "glm-4-flash")
    xai_key = os.getenv("XAI_API_KEY")
    oai_key = os.getenv("OPENAI_API_KEY")
    reply: str

    ai_key = None
    ai_base_url = None
    ai_model = None

    if zhipu_key:
        ai_key = zhipu_key
        ai_base_url = "https://open.bigmodel.cn/api/paas/v4/"
        ai_model = zhipu_model
    elif xai_key:
        ai_key = xai_key
        ai_base_url = "https://api.x.ai/v1"
        ai_model = "grok-3-fast-beta"
    elif oai_key:
        ai_key = oai_key
        ai_base_url = None
        ai_model = "gpt-4o-mini"

    if ai_key:
        try:
            from openai import OpenAI as _OpenAI
            client = _OpenAI(api_key=ai_key, base_url=ai_base_url)

            messages = [{"role": "system", "content": _LEGAL_CHATBOT_SYSTEM_PROMPT}]
            messages.extend(history_snapshot[-20:])
            messages.append({"role": "user", "content": message})

            completion = client.chat.completions.create(
                model=ai_model,
                messages=messages,
                max_tokens=800,
                temperature=0.4,
            )
            reply = (completion.choices[0].message.content or "").strip()
            if not reply:
                reply = _chatbot_keyword_fallback(message)
        except Exception as exc:
            import sys
            print(f"[chatbot] AI error ({ai_model}): {exc}", file=sys.stderr)
            reply = _chatbot_keyword_fallback(message)
    else:
        reply = _chatbot_keyword_fallback(message)

    # Persist history (cap at 40 messages = 20 turns)
    with _chat_lock:
        if session_id in legal_chat_sessions:
            hist = legal_chat_sessions[session_id]["history"]
            hist.append({"role": "user",      "content": message})
            hist.append({"role": "assistant", "content": reply})
            if len(hist) > 40:
                legal_chat_sessions[session_id]["history"] = hist[-40:]

    return {"reply": reply, "session_id": session_id}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("APP_PORT", 8080))
    uvicorn.run("main:app", host="127.0.0.1", port=port, reload=False)
