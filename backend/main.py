"""
main.py — Quanby Legal Contract AI Agent Backend
FastAPI application with contract analysis, chat, and generation endpoints
"""

import os
import json
import time
from typing import Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

from contract_parser import extract_text, clean_text, get_contract_summary_for_context
from ai_engine import analyze_contract, chat_about_contract, generate_contract

load_dotenv()

app = FastAPI(
    title="Quanby Legal Contract AI Agent",
    description="AI-powered contract analysis for Philippine law compliance",
    version="1.0.0"
)

# CORS — allow frontend to call API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory session store (production would use Redis)
# Maps session_id -> {"contract_text": str, "filename": str, "history": list, "analysis": dict}
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
    # Validate file type
    filename = file.filename or "contract"
    if not any(filename.lower().endswith(ext) for ext in [".pdf", ".docx", ".doc", ".txt"]):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Please upload PDF, DOCX, or TXT files."
        )
    
    # Read file
    file_bytes = await file.read()
    if len(file_bytes) > 20 * 1024 * 1024:  # 20MB limit
        raise HTTPException(status_code=400, detail="File too large. Maximum 20MB.")
    
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Empty file uploaded.")
    
    # Extract text
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
    
    # Get AI analysis (use summary for large docs)
    context_text = get_contract_summary_for_context(contract_text, max_length=12000)
    result = analyze_contract(context_text, filename)
    
    # Store session
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
    """
    Chat about an uploaded contract.
    Session must have a contract loaded via /api/analyze first.
    """
    session = sessions.get(request.session_id)
    
    if not session:
        raise HTTPException(
            status_code=404,
            detail="No contract loaded for this session. Please upload a contract first."
        )
    
    contract_text = session["contract_text"]
    filename = session["filename"]
    history = session["history"]
    
    # Get AI response
    result = chat_about_contract(
        contract_text=contract_text,
        conversation_history=history,
        user_message=request.message,
        filename=filename
    )
    
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Chat failed"))
    
    # Update history
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
    """
    Generate a contract from a template using AI.
    """
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


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("APP_PORT", 8080))
    uvicorn.run("main:app", host="127.0.0.1", port=port, reload=False)
