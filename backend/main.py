"""
main.py — Quanby Legal Backend
FastAPI application: Contract AI + SSO Auth + Onboarding + Certification
"""

import os
import json
import time
import uuid
import base64
from typing import Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Form, Header, Request, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel
from dotenv import load_dotenv

from contract_parser import extract_text, clean_text, get_contract_summary_for_context
from ai_engine import analyze_contract, chat_about_contract, generate_contract
from auth import (
    create_jwt, verify_jwt, get_oauth_urls, validate_oauth_state,
    google_get_user_info, facebook_get_user_info, linkedin_get_user_info,
    APP_URL
)
from onboarding import (
    get_or_create_user, get_user, update_user,
    save_test_session, get_test_session,
    generate_certificate_id, get_certificate_html, get_certificate_email_html
)
from question_bank import get_randomized_test, grade_test

load_dotenv()

app = FastAPI(
    title="Quanby Legal",
    description="Supreme Court-Accredited Electronic Notarization Platform",
    version="2.0.0"
)

# Fix 16: Restrict CORS origins — no wildcard, keep allow_credentials=True
_FRONTEND_URL = os.getenv("FRONTEND_URL", "https://legal.quanbyai.com")
_APP_URL       = os.getenv("APP_URL", "https://legal.quanbyai.com")
_ALLOWED_ORIGINS = list({_FRONTEND_URL, _APP_URL})  # deduplicate if same

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory session store (production would use Redis)
sessions: dict = {}


# ─── Models ───────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    session_id: str
    message: str

class GenerateRequest(BaseModel):
    template_type: str
    parameters: dict = {}


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    xai_key = os.getenv("XAI_API_KEY", "")
    return {
        "status": "ok",
        "service": "Quanby Legal Contract AI Agent",
        "version": "1.0.0",
        "ai_configured": bool(xai_key and xai_key.startswith("xai-")),
        "timestamp": int(time.time())
    }


@app.post("/api/analyze")
async def analyze_endpoint(
    file: UploadFile = File(...),
    session_id: str = Form(default="default")
):
    """
    Upload a PDF or DOCX contract and get AI analysis.
    Returns structured analysis with parties, risks, obligations, etc.
    """
    filename = file.filename or "contract"
    if not any(filename.lower().endswith(ext) for ext in [".pdf", ".docx", ".doc", ".txt"]):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Please upload PDF, DOCX, or TXT files."
        )

    file_bytes = await file.read()
    if len(file_bytes) > 20 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large. Maximum 20MB.")

    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Empty file uploaded.")

    try:
        raw_text = extract_text(file_bytes, filename)
        contract_text = clean_text(raw_text)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    if len(contract_text.strip()) < 50:
        raise HTTPException(
            status_code=422,
            detail="Could not extract sufficient text from the document. Please ensure the file is not scanned/image-only."
        )

    context_text = get_contract_summary_for_context(contract_text, max_length=12000)
    result = analyze_contract(context_text, filename)

    sessions[session_id] = {
        "contract_text": context_text,
        "filename": filename,
        "history": [],
        "analysis": result.get("analysis", {}),
        "created_at": int(time.time())
    }

    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "AI analysis failed"))

    return {
        "success": True,
        "session_id": session_id,
        "filename": filename,
        "text_length": len(contract_text),
        "analysis": result["analysis"],
        "tokens_used": result.get("tokens_used")
    }


@app.post("/api/chat")
async def chat_endpoint(request: ChatRequest):
    """Chat about an uploaded contract."""
    session = sessions.get(request.session_id)

    if not session:
        raise HTTPException(
            status_code=404,
            detail="No contract loaded for this session. Please upload a contract first."
        )

    contract_text = session["contract_text"]
    filename = session["filename"]
    history = session["history"]

    result = chat_about_contract(
        contract_text=contract_text,
        conversation_history=history,
        user_message=request.message,
        filename=filename
    )

    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Chat failed"))

    history.append({"role": "user", "content": request.message})
    history.append({"role": "assistant", "content": result["response"]})
    sessions[request.session_id]["history"] = history

    return {
        "success": True,
        "response": result["response"],
        "tokens_used": result.get("tokens_used")
    }


@app.post("/api/generate")
async def generate_endpoint(request: GenerateRequest):
    """Generate a contract from a template using AI."""
    valid_templates = [
        "deed_of_sale", "lease_agreement", "employment_contract",
        "service_agreement", "loan_agreement", "partnership_agreement",
        "nda", "memorandum_of_agreement", "joint_venture", "power_of_attorney"
    ]

    if request.template_type not in valid_templates:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid template type. Choose from: {', '.join(valid_templates)}"
        )

    result = generate_contract(request.template_type, request.parameters)

    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Generation failed"))

    return {
        "success": True,
        "contract_type": result["contract_type"],
        "contract_text": result["contract_text"],
        "tokens_used": result.get("tokens_used")
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

# ─── Models ───────────────────────────────────────────────────────────────────

class RoleSelectRequest(BaseModel):
    role: str

class ProfileRequest(BaseModel):
    first_name: str
    last_name: str
    phone: str
    role: str
    firm_name: Optional[str] = None
    ibp_number: Optional[str] = None
    ptc_number: Optional[str] = None
    legal_address: Optional[str] = None
    num_employees: Optional[str] = None
    mayors_permit: Optional[str] = None
    bir_number: Optional[str] = None
    organization: Optional[str] = None
    position: Optional[str] = None

class TestAnswerRequest(BaseModel):
    test_session_id: str
    answers: dict

class RetakePaymentRequest(BaseModel):
    user_id: str
    payment_method: str


# ─── Helper ───────────────────────────────────────────────────────────────────

def get_current_user(
    authorization: Optional[str] = None,
    cookie_token: Optional[str] = None,
) -> Optional[dict]:
    """
    Extract user from Bearer token (Authorization header) or HttpOnly session cookie.
    Fix 14/15: Checks both sources; cookie takes lower priority than header.
    """
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
    elif cookie_token:
        token = cookie_token
    if not token:
        return None
    payload = verify_jwt(token)
    if not payload:
        return None
    return get_user(payload.get("user_id", ""))


# ─── OAuth URLs ───────────────────────────────────────────────────────────────

@app.get("/api/auth/providers")
async def auth_providers():
    """Return OAuth login URLs (each includes a unique CSRF state token)."""
    return {"providers": get_oauth_urls()}


# ─── Google OAuth ─────────────────────────────────────────────────────────────

@app.get("/api/auth/callback/google")
async def google_callback(code: str, state: Optional[str] = None):
    """Handle Google OAuth callback."""
    # Fix 13: Validate CSRF state before processing
    if not state or not validate_oauth_state(state):
        raise HTTPException(400, "Invalid or expired OAuth state. Please try logging in again.")
    redirect_uri = f"{APP_URL}/api/auth/callback/google"
    user_info = await google_get_user_info(code, redirect_uri)
    user = await get_or_create_user(user_info)  # Fix 18: await async call
    token = create_jwt({"user_id": user["id"], "email": user["email"]})
    step = user.get("onboarding_step", "role_select")
    # Fix 14: Deliver token via secure HttpOnly cookie, not URL query param
    response = RedirectResponse(url=f"{APP_URL}/auth-complete?step={step}", status_code=302)
    response.set_cookie(
        "ql_session", token,
        httponly=True, secure=True, samesite="lax",
        max_age=86400 * 7, path="/"
    )
    return response


@app.get("/api/auth/callback/facebook")
async def facebook_callback(code: str, state: Optional[str] = None):
    """Handle Facebook OAuth callback."""
    # Fix 13: Validate CSRF state before processing
    if not state or not validate_oauth_state(state):
        raise HTTPException(400, "Invalid or expired OAuth state. Please try logging in again.")
    redirect_uri = f"{APP_URL}/api/auth/callback/facebook"
    user_info = await facebook_get_user_info(code, redirect_uri)
    user = await get_or_create_user(user_info)  # Fix 18: await async call
    token = create_jwt({"user_id": user["id"], "email": user["email"]})
    step = user.get("onboarding_step", "role_select")
    # Fix 14: Deliver token via secure HttpOnly cookie, not URL query param
    response = RedirectResponse(url=f"{APP_URL}/auth-complete?step={step}", status_code=302)
    response.set_cookie(
        "ql_session", token,
        httponly=True, secure=True, samesite="lax",
        max_age=86400 * 7, path="/"
    )
    return response


@app.get("/api/auth/callback/linkedin")
async def linkedin_callback(code: str, state: Optional[str] = None):
    """Handle LinkedIn OAuth callback."""
    # Fix 13: Validate CSRF state before processing
    if not state or not validate_oauth_state(state):
        raise HTTPException(400, "Invalid or expired OAuth state. Please try logging in again.")
    redirect_uri = f"{APP_URL}/api/auth/callback/linkedin"
    user_info = await linkedin_get_user_info(code, redirect_uri)
    user = await get_or_create_user(user_info)  # Fix 18: await async call
    token = create_jwt({"user_id": user["id"], "email": user["email"]})
    step = user.get("onboarding_step", "role_select")
    # Fix 14: Deliver token via secure HttpOnly cookie, not URL query param
    response = RedirectResponse(url=f"{APP_URL}/auth-complete?step={step}", status_code=302)
    response.set_cookie(
        "ql_session", token,
        httponly=True, secure=True, samesite="lax",
        max_age=86400 * 7, path="/"
    )
    return response


# ─── User Session ─────────────────────────────────────────────────────────────

@app.get("/api/auth/me")
async def get_me(
    authorization: Optional[str] = Header(None),
    ql_session: Optional[str] = Cookie(None),  # Fix 15: accept cookie token
):
    """Get current user info."""
    user = get_current_user(authorization, ql_session)
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
    ql_session: Optional[str] = Cookie(None),  # Fix 15
):
    """Set user role: attorney or client."""
    user = get_current_user(authorization, ql_session)
    if not user:
        raise HTTPException(401, "Unauthorized")
    if req.role not in ("attorney", "client"):
        raise HTTPException(400, "Role must be 'attorney' or 'client'")

    await update_user(user["id"], {"role": req.role, "onboarding_step": "profile"})  # Fix 18: await
    return {"success": True, "next_step": "profile"}


# ─── Onboarding Step 2: Profile ───────────────────────────────────────────────

@app.post("/api/onboarding/profile")
async def save_profile(
    req: ProfileRequest,
    authorization: Optional[str] = Header(None),
    ql_session: Optional[str] = Cookie(None),  # Fix 15
):
    """Save user profile information."""
    user = get_current_user(authorization, ql_session)
    if not user:
        raise HTTPException(401, "Unauthorized")

    profile = {
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

    # Fix 18: await async update_user
    await update_user(user["id"], {
        "profile": profile,
        "first_name": req.first_name,
        "last_name": req.last_name,
        "onboarding_step": "test"
    })
    return {"success": True, "next_step": "test"}


# ─── Onboarding Step 3: Certification Test ───────────────────────────────────

@app.get("/api/certification/start")
async def start_test(
    authorization: Optional[str] = Header(None),
    ql_session: Optional[str] = Cookie(None),  # Fix 15
):
    """Start a new randomized certification test. Returns 15 questions (no answers)."""
    user = get_current_user(authorization, ql_session)
    if not user:
        raise HTTPException(401, "Unauthorized")
    if not user.get("role"):
        raise HTTPException(400, "Complete role selection first")

    # Fix 17: get_randomized_test now returns (client_questions, answer_key)
    client_questions, answer_key = get_randomized_test(role=user["role"], count=15)
    test_session_id = str(uuid.uuid4())

    # Fix 17: Store answer_key server-side in the test session
    save_test_session(test_session_id, {
        "user_id": user["id"],
        "questions": client_questions,
        "answer_key": answer_key,
        "started_at": time.time(),
        "expires_at": time.time() + 3600,
    })

    # client_questions already has no 'answer' field (enforced by question_bank)
    return {
        "success": True,
        "test_session_id": test_session_id,
        "questions": client_questions,
        "total": 15,
        "passing_score": 80,
        "time_limit_minutes": 60,
        "role": user["role"]
    }


@app.post("/api/certification/submit")
async def submit_test(
    req: TestAnswerRequest,
    authorization: Optional[str] = Header(None),
    ql_session: Optional[str] = Cookie(None),  # Fix 15
):
    """Submit test answers for grading."""
    user = get_current_user(authorization, ql_session)
    if not user:
        raise HTTPException(401, "Unauthorized")

    session = get_test_session(req.test_session_id)
    if not session:
        raise HTTPException(404, "Test session not found or expired")
    if session["user_id"] != user["id"]:
        raise HTTPException(403, "Forbidden")
    if time.time() > session["expires_at"]:
        raise HTTPException(400, "Test session has expired")

    # Fix 17: Pass questions + answer_key + user_answers to grade_test
    result = grade_test(session["questions"], session["answer_key"], req.answers)

    retake_count = user.get("retake_count", 0)
    updates = {
        "test_result": result,
        "retake_count": retake_count + (0 if result["passed"] else 1),
    }

    if result["passed"]:
        cert_id = generate_certificate_id(user.get("role", "client"))
        updates.update({
            "certificate_id": cert_id,
            "certificate_status": "probationary",
            "onboarding_step": "liveness",
        })

    await update_user(user["id"], updates)  # Fix 18: await
    updated_user = get_user(user["id"])

    response = {
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
            "message": "🎉 Congratulations! You passed. Your probationary certificate has been issued and emailed to you.",
            "next_step": "liveness",
        })
    else:
        response.update({
            "retake_fee_php": 500,
            "retake_count": updates["retake_count"],
            "message": f"You scored {result['score_pct']}%. The passing score is 80% (12/15). A ₱500 retake fee applies.",
            "payment_options": ["gcash", "bank_transfer"],
            "gcash_number": os.getenv("GCASH_NUMBER", "09XXXXXXXXX"),
            "bank_name": os.getenv("BANK_NAME", "BDO"),
            "bank_account": os.getenv("BANK_ACCOUNT", "XXXX-XXXX-XXXX"),
            "bank_account_name": os.getenv("BANK_ACCOUNT_NAME", "Quanby Solutions, Inc."),
        })

    return response


# ─── Onboarding Step 4: Liveness + National ID ───────────────────────────────

@app.post("/api/onboarding/liveness")
async def submit_liveness(
    selfie: UploadFile = File(...),
    authorization: Optional[str] = Header(None),
    ql_session: Optional[str] = Cookie(None),  # Fix 15
):
    """Submit webcam selfie for liveness verification."""
    user = get_current_user(authorization, ql_session)
    if not user:
        raise HTTPException(401, "Unauthorized")

    selfie_bytes = await selfie.read()
    if len(selfie_bytes) < 1000:
        raise HTTPException(400, "Invalid image — file too small")

    selfie_path = f"data/selfies/{user['id']}.jpg"
    import os as _os
    _os.makedirs("data/selfies", exist_ok=True)
    with open(selfie_path, "wb") as f:
        f.write(selfie_bytes)

    await update_user(user["id"], {"liveness_verified": True})  # Fix 18: await

    updated = get_user(user["id"])
    if updated.get("national_id_uploaded"):
        await update_user(user["id"], {"onboarding_step": "survey"})  # Fix 18: await
        return {"success": True, "message": "Liveness verified ✅", "next_step": "survey"}

    return {"success": True, "message": "Liveness verified ✅", "next_step": "national_id"}


@app.post("/api/onboarding/national-id")
async def upload_national_id(
    national_id: UploadFile = File(...),
    authorization: Optional[str] = Header(None),
    ql_session: Optional[str] = Cookie(None),  # Fix 15
):
    """Upload national ID document."""
    user = get_current_user(authorization, ql_session)
    if not user:
        raise HTTPException(401, "Unauthorized")

    id_bytes = await national_id.read()
    if len(id_bytes) < 1000:
        raise HTTPException(400, "Invalid file")

    import os as _os
    _os.makedirs("data/national_ids", exist_ok=True)
    ext = national_id.filename.split(".")[-1] if national_id.filename else "jpg"
    with open(f"data/national_ids/{user['id']}.{ext}", "wb") as f:
        f.write(id_bytes)

    await update_user(user["id"], {"national_id_uploaded": True})  # Fix 18: await

    updated = get_user(user["id"])
    if updated.get("liveness_verified"):
        await update_user(user["id"], {"onboarding_step": "survey"})  # Fix 18: await
        return {"success": True, "message": "National ID uploaded ✅", "next_step": "survey"}

    return {"success": True, "message": "National ID uploaded ✅", "next_step": "liveness"}


# ─── Onboarding Step 5: Full Certification ───────────────────────────────────

@app.post("/api/onboarding/complete")
async def complete_onboarding(
    authorization: Optional[str] = Header(None),
    ql_session: Optional[str] = Cookie(None),  # Fix 15
):
    """
    Mark onboarding as complete → upgrade cert from probationary to certified.
    Requires: liveness ✅ + national ID ✅ + test passed ✅
    """
    user = get_current_user(authorization, ql_session)
    if not user:
        raise HTTPException(401, "Unauthorized")

    if not user.get("liveness_verified"):
        raise HTTPException(400, "Liveness verification required")
    if not user.get("national_id_uploaded"):
        raise HTTPException(400, "National ID upload required")
    if not user.get("test_result", {}).get("passed"):
        raise HTTPException(400, "Certification test must be passed first")

    await update_user(user["id"], {  # Fix 18: await
        "certificate_status": "certified",
        "onboarding_step": "certified"
    })

    return {
        "success": True,
        "certificate_id": user["certificate_id"],
        "message": "🎉 Full certification complete! Download your certificate and present it to the Supreme Court.",
        "next_step": "certified"
    }


# ─── Certificate Download ─────────────────────────────────────────────────────

@app.get("/api/certificate/{certificate_id}")
async def get_certificate(
    certificate_id: str,
    authorization: Optional[str] = Header(None),
    ql_session: Optional[str] = Cookie(None),  # Fix 15
):
    """Download printable HTML certificate."""
    user = get_current_user(authorization, ql_session)
    if not user:
        raise HTTPException(401, "Unauthorized")
    if user.get("certificate_id") != certificate_id:
        raise HTTPException(403, "Certificate not found for this account")

    html = get_certificate_html(user)
    return HTMLResponse(content=html, status_code=200)


@app.get("/api/verify/{certificate_id}")
async def verify_certificate(certificate_id: str):
    """Public certificate verification endpoint."""
    from onboarding import USERS
    for uid, user in USERS.items():
        if user.get("certificate_id") == certificate_id:
            return {
                "valid": True,
                "certificate_id": certificate_id,
                "name": f"{user.get('first_name', '')} {user.get('last_name', '')}",
                "role": user.get("role"),
                "status": user.get("certificate_status"),
                "issued_at": user.get("created_at"),
            }
    return {"valid": False, "certificate_id": certificate_id}


# ─── Retake Payment ───────────────────────────────────────────────────────────

@app.post("/api/certification/retake-payment")
async def submit_retake_payment(
    req: RetakePaymentRequest,
    authorization: Optional[str] = Header(None),
    ql_session: Optional[str] = Cookie(None),  # Fix 15
):
    """
    Record retake payment confirmation.
    In production: integrate with PayMongo/GCash webhook.
    """
    user = get_current_user(authorization, ql_session)
    if not user:
        raise HTTPException(401, "Unauthorized")

    await update_user(user["id"], {"retake_payment_pending": True})  # Fix 18: await

    return {
        "success": True,
        "message": f"Payment via {req.payment_method} recorded. Once confirmed, you may retake the test.",
        "instructions": {
            "gcash": f"Send ₱500 to {os.getenv('GCASH_NUMBER', '09XX-XXX-XXXX')} with reference: RETAKE-{user['id'][:8].upper()}",
            "bank_transfer": f"Transfer ₱500 to {os.getenv('BANK_NAME', 'BDO')} Acc: {os.getenv('BANK_ACCOUNT', 'XXXX')} | Account Name: Quanby Solutions, Inc. | Ref: RETAKE-{user['id'][:8].upper()}"
        }
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("APP_PORT", 8080))
    uvicorn.run("main:app", host="127.0.0.1", port=port, reload=False)
