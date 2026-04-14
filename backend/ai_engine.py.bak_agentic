"""
ai_engine.py — Contract AI Logic for Quanby Legal
Powered by xAI Grok via OpenAI-compatible API
Focused on Philippine law, Civil Code, and Supreme Court notarization standards
"""

import os
import json
from typing import Optional
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

XAI_API_KEY = os.getenv("XAI_API_KEY")
XAI_BASE_URL = "https://api.x.ai/v1"
MODEL = "grok-3-fast-beta"  # xAI Grok fast model

# Fallback model if primary not available
FALLBACK_MODEL = "grok-beta"

SYSTEM_PROMPT = """You are the Quanby Legal Contract AI Agent — an expert legal AI specializing in Philippine law, corporate compliance, and contract analysis. You are integrated into Quanby Legal, the first and only Supreme Court-accredited electronic notarization platform in the Philippines.

## YOUR EXPERTISE

### Philippine Legal Framework
- **Civil Code of the Philippines** (Republic Act No. 386) — obligations, contracts, property, family law
- **Electronic Commerce Act** (Republic Act No. 8792) — electronic documents and signatures
- **Electronic Notarization Rules** (A.M. No. 24-10-14-SC) — Supreme Court rules for e-notarization
- **Corporation Code** (Republic Act No. 11232) — corporate documents and compliance
- **Labor Code of the Philippines** (Presidential Decree No. 442) — employment contracts
- **National Land Use Act** and property laws for real estate contracts
- **Consumer Act** (Republic Act No. 7394) — consumer protection provisions
- **Data Privacy Act** (Republic Act No. 10173) — data handling obligations
- **Anti-Money Laundering Act** — KYC and financial contract compliance
- **DICT National PKI standards** — digital identity verification requirements
- **Revised Penal Code** — legal consequences of fraudulent contracts

### Contract Analysis Capabilities
1. **Party Identification** — Extract all parties with their roles, legal capacity, and representation authority
2. **Obligation Mapping** — Identify reciprocal duties, timelines, and performance standards
3. **Payment Terms** — Extract amounts, schedules, penalties, and currency specifications
4. **Key Dates** — Effectivity dates, deadlines, renewal dates, termination notice periods
5. **Risk Clause Detection** — Flag unfavorable terms, one-sided provisions, unconscionable clauses
6. **Compliance Check** — Verify against Philippine law requirements and notarization standards
7. **Missing Clause Alerts** — Identify standard clauses that are absent (e.g., force majeure, dispute resolution, governing law)
8. **Notarization Readiness** — Assess if document is ready for electronic notarization under A.M. No. 24-10-14-SC

## RESPONSE STYLE
- Be precise, professional, and actionable
- Always cite specific Philippine law provisions when flagging issues
- Use clear risk levels: 🔴 HIGH RISK, 🟡 MEDIUM RISK, 🟢 LOW RISK, ℹ️ INFO
- Support both English and Filipino (Tagalog) responses
- Be thorough but concise — focus on what matters for the client

## IMPORTANT DISCLAIMERS
- Always remind users that AI analysis does not constitute legal advice
- Recommend consultation with a licensed Philippine attorney for high-stakes decisions
- Note that Quanby Legal's certified Electronic Notary Publics (ENPs) are available for document notarization"""


def get_client() -> OpenAI:
    """Initialize xAI Grok client."""
    if not XAI_API_KEY:
        raise ValueError("XAI_API_KEY not configured")
    return OpenAI(
        api_key=XAI_API_KEY,
        base_url=XAI_BASE_URL,
    )


def analyze_contract(contract_text: str, filename: str) -> dict:
    """
    Perform comprehensive AI analysis of a contract.
    Returns structured analysis with parties, risks, obligations, etc.
    """
    client = get_client()
    
    analysis_prompt = f"""Please analyze this contract document and provide a comprehensive legal review.

DOCUMENT: {filename}

CONTRACT TEXT:
---
{contract_text}
---

Provide your analysis in the following JSON structure:
{{
  "contract_type": "Type of contract (e.g., Deed of Sale, Employment Contract, Lease Agreement, Service Agreement, etc.)",
  "summary": "2-3 sentence executive summary of what this contract does",
  "parties": [
    {{
      "name": "Full legal name",
      "role": "Role in contract (e.g., Seller, Buyer, Employer, Employee, Lessor, Lessee)",
      "type": "Individual or Corporation",
      "notes": "Any concerns about authority, capacity, or representation"
    }}
  ],
  "key_dates": [
    {{
      "label": "Date type (e.g., Effectivity Date, Termination Date, Payment Due)",
      "date": "Date or period as stated",
      "risk": "none/low/medium/high",
      "note": "Any concern about this date"
    }}
  ],
  "payment_terms": {{
    "total_amount": "Total contract value if stated",
    "currency": "PHP or other currency",
    "schedule": "Payment schedule description",
    "penalties": "Late payment penalties if any",
    "notes": "Any payment-related concerns"
  }},
  "obligations": [
    {{
      "party": "Party name",
      "obligation": "Specific obligation",
      "deadline": "When it must be done",
      "risk": "none/low/medium/high"
    }}
  ],
  "risk_flags": [
    {{
      "severity": "high/medium/low/info",
      "title": "Short title of the issue",
      "description": "Detailed explanation of the risk",
      "clause": "Relevant clause or section reference",
      "law_reference": "Applicable Philippine law (if any)",
      "recommendation": "What to do about this"
    }}
  ],
  "missing_clauses": [
    {{
      "clause": "Missing clause name",
      "importance": "high/medium/low",
      "why_needed": "Why this clause is important under Philippine law",
      "recommendation": "Suggested language or approach"
    }}
  ],
  "compliance_check": {{
    "civil_code": "Compliant/Non-compliant/Needs Review",
    "electronic_commerce_act": "Compliant/Non-compliant/N/A",
    "notarization_ready": "Yes/No/Needs Updates",
    "notarization_notes": "What needs to be done for e-notarization",
    "other_laws": "Any other relevant compliance notes"
  }},
  "overall_risk": "high/medium/low",
  "overall_score": 85,
  "recommendation": "Overall recommendation and next steps"
}}

Be thorough and precise. Flag any clause that could be disadvantageous to either party. Cite specific Philippine laws."""

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": analysis_prompt}
            ],
            temperature=0.1,
            max_tokens=4000,
        )
        
        raw_response = response.choices[0].message.content
        
        # Try to parse JSON from response
        try:
            # Find JSON in the response
            json_start = raw_response.find('{')
            json_end = raw_response.rfind('}') + 1
            if json_start != -1 and json_end > json_start:
                json_str = raw_response[json_start:json_end]
                analysis = json.loads(json_str)
            else:
                analysis = {"raw_analysis": raw_response, "parse_error": True}
        except json.JSONDecodeError:
            analysis = {"raw_analysis": raw_response, "parse_error": True}
        
        return {
            "success": True,
            "filename": filename,
            "analysis": analysis,
            "tokens_used": response.usage.total_tokens if response.usage else None
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "filename": filename
        }


def chat_about_contract(
    contract_text: str,
    conversation_history: list,
    user_message: str,
    filename: str = "contract"
) -> dict:
    """
    Conversational interface about an uploaded contract.
    Maintains conversation history for context.
    """
    client = get_client()
    
    # Build messages list
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT + f"\n\nThe user has uploaded a contract called '{filename}'. Here is the contract text for reference:\n\n---\n{contract_text}\n---\n\nAnswer questions about this specific contract. Be precise and cite specific sections when possible."}
    ]
    
    # Add conversation history (limit to last 10 exchanges to stay within context)
    for msg in conversation_history[-20:]:
        messages.append(msg)
    
    # Add current user message
    messages.append({"role": "user", "content": user_message})
    
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            temperature=0.3,
            max_tokens=1500,
        )
        
        assistant_message = response.choices[0].message.content
        
        return {
            "success": True,
            "response": assistant_message,
            "tokens_used": response.usage.total_tokens if response.usage else None
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "response": f"I encountered an error processing your request: {str(e)}"
        }


def generate_contract(template_type: str, parameters: dict) -> dict:
    """
    Generate a contract from a template using AI.
    Supports various Philippine contract types.
    """
    client = get_client()
    
    template_descriptions = {
        "deed_of_sale": "Deed of Absolute Sale for real property under Philippine law",
        "lease_agreement": "Contract of Lease for residential or commercial property",
        "employment_contract": "Employment Contract compliant with Philippine Labor Code",
        "service_agreement": "Service Agreement / Professional Services Contract",
        "loan_agreement": "Loan Agreement with promissory note provisions",
        "partnership_agreement": "Partnership Agreement under Philippine Civil Code",
        "nda": "Non-Disclosure Agreement (Confidentiality Agreement)",
        "memorandum_of_agreement": "Memorandum of Agreement (MOA)",
        "joint_venture": "Joint Venture Agreement",
        "power_of_attorney": "Special Power of Attorney (SPA)",
    }
    
    template_desc = template_descriptions.get(template_type, template_type.replace('_', ' ').title())
    
    # Format parameters as readable text
    params_text = "\n".join([f"- {k.replace('_', ' ').title()}: {v}" for k, v in parameters.items() if v])
    
    generation_prompt = f"""Generate a complete, legally sound {template_desc} for the Philippines.

CONTRACT PARAMETERS:
{params_text}

Requirements:
1. Follow Philippine law requirements (Civil Code, relevant statutes)
2. Include all standard clauses for this contract type
3. Add force majeure clause
4. Add governing law clause (Philippine law, proper courts)
5. Add dispute resolution clause
6. Include acknowledgment/notarization block ready for e-notarization under A.M. No. 24-10-14-SC
7. Use clear, professional legal language
8. Number all sections and clauses
9. Include all parties' signature blocks

Generate the complete contract document now:"""

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": generation_prompt}
            ],
            temperature=0.2,
            max_tokens=3000,
        )
        
        contract_text = response.choices[0].message.content
        
        return {
            "success": True,
            "contract_type": template_type,
            "contract_text": contract_text,
            "tokens_used": response.usage.total_tokens if response.usage else None
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
