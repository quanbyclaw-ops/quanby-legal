"""Patch backend/main.py and backend/email_service.py for KYC retake flow."""
import os
import re

BASE = r'C:\Users\Claw\.openclaw\workspace\quanby-legal\backend'

# ════════════════════════════════════════════════════════════════════════════
# 1. email_service.py — add send_test_fail_email
# ════════════════════════════════════════════════════════════════════════════
EMAIL_PATH = os.path.join(BASE, 'email_service.py')
email_content = open(EMAIL_PATH, 'r', encoding='utf-8').read()

FAIL_EMAIL_FUNC = '''

def send_test_fail_email(user: dict, score_pct: float, retake_url: str = "https://legal.quanbyai.com/?retake=1") -> None:
    """Send exam failure notification with retake link. Fire-and-forget."""
    to_email = user.get("email", "")
    if not to_email:
        return
    first_name = user.get("first_name", "Attorney")
    last_name = user.get("last_name", "")
    full_name = f"{first_name} {last_name}".strip()

    subject = "ENP Certification Exam Result \\u2014 Quanby Legal"

    text_body = f"""Hello {full_name},

Thank you for taking the ENP Certification Exam on the Quanby Legal Platform.

Your Score: {score_pct}%
Required to Pass: 70%
Result: NOT PASSED

To retake the exam, a \\u20b1500 retake fee is required. Click the link below to proceed with payment and schedule your retake:

Retake Exam: {retake_url}

We encourage you to review the course module before retaking:
https://legal.quanbyai.com/mastering-quanby-legal.pdf

If you have any questions, please contact us at legal@quanby.legal.

The Quanby Legal Team
"""

    html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
  <div style="background:#0a1628;padding:20px;border-radius:8px;text-align:center;margin-bottom:24px;">
    <h1 style="color:#c9a84c;margin:0;">&#9878;&#65039; Quanby Legal</h1>
    <p style="color:#fff;margin:8px 0 0;">ENP Certification Platform</p>
  </div>
  <h2 style="color:#0a1628;">Hello {full_name},</h2>
  <p>Thank you for taking the ENP Certification Exam.</p>
  <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:20px;margin:20px 0;text-align:center;">
    <div style="font-size:2.5rem;margin-bottom:8px;">&#10060;</div>
    <h3 style="color:#dc2626;margin:0 0 8px;">Not Passed</h3>
    <p style="margin:0;color:#666;">Your Score: <strong>{score_pct}%</strong> &nbsp;|&nbsp; Required: <strong>70%</strong></p>
  </div>
  <p>Don\'t be discouraged! You may retake the exam after paying the <strong>&#8369;500 retake fee</strong>.</p>
  <p>We recommend reviewing the course module before retaking:</p>
  <p><a href="https://legal.quanbyai.com/mastering-quanby-legal.pdf" style="color:#c9a84c;">&#128218; Download Course Module (PDF)</a></p>
  <div style="text-align:center;margin:28px 0;">
    <a href="{retake_url}" style="background:#0a1628;color:#c9a84c;padding:14px 28px;border-radius:6px;text-decoration:none;font-weight:bold;font-size:1rem;">
      &#127891; Retake Exam (&#8369;500 fee) &rarr;
    </a>
  </div>
  <p style="color:#666;font-size:0.85rem;">If you have questions, contact us at <a href="mailto:legal@quanby.legal">legal@quanby.legal</a></p>
  <p style="color:#666;font-size:12px;text-align:center;">The Quanby Legal Team | legal.quanbyai.com</p>
</body>
</html>"""

    def _send():
        send_email(to_email, subject, html_body, text_body)

    t = threading.Thread(target=_send, daemon=True, name=f"fail-email-{user.get('id', 'unknown')}")
    t.start()
'''

if 'send_test_fail_email' not in email_content:
    email_content = email_content.rstrip() + '\n' + FAIL_EMAIL_FUNC + '\n'
    open(EMAIL_PATH, 'w', encoding='utf-8').write(email_content)
    print("send_test_fail_email added to email_service.py: YES")
else:
    print("send_test_fail_email already exists in email_service.py")

# ════════════════════════════════════════════════════════════════════════════
# 2. main.py patches
# ════════════════════════════════════════════════════════════════════════════
MAIN_PATH = os.path.join(BASE, 'main.py')
main_content = open(MAIN_PATH, 'r', encoding='utf-8').read()

# 2a. Import send_test_fail_email from email_service
OLD_EMAIL_IMPORT = 'from email_service import send_welcome_email'
NEW_EMAIL_IMPORT = 'from email_service import send_welcome_email, send_test_fail_email'
if OLD_EMAIL_IMPORT in main_content:
    main_content = main_content.replace(OLD_EMAIL_IMPORT, NEW_EMAIL_IMPORT)
    print("Import send_test_fail_email: YES")
elif 'send_test_fail_email' in main_content:
    print("send_test_fail_email import already present")
else:
    # Try to add after any email_service import
    main_content = main_content.replace(
        'from email_service import',
        'from email_service import send_test_fail_email\nfrom email_service import',
    )
    print("send_test_fail_email import injected at top: check manually")

# 2b. Fire fail email in submit_test endpoint — after "return response"
# Find the block where failed result is set and add the email call before "return response"
# The submit_test endpoint ends with "return response"
# We inject after the else block for failed

OLD_FAIL_BLOCK = '''    if result["passed"]:
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
            "certificate_id": updates["certificate_id"],'''

# Check if fail email fire is already there
if 'send_test_fail_email' in main_content and 'threading.Thread(target=send_test_fail_email' in main_content:
    print("Fail email fire already in submit_test")
else:
    # Add fire-and-forget fail email after await update_user
    OLD_RETURN_RESPONSE = '''    await update_user(user["id"], updates)

    response: dict = {
        "success": True,
        "passed": result["passed"],
        "score": result["score_pct"],
        "correct": result["correct"],
        "total": result["total"],
        "passing_score": result["passing_score"],
    }

    if result["passed"]:'''
    
    NEW_RETURN_RESPONSE = '''    await update_user(user["id"], updates)

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

    if result["passed"]:'''
    
    if OLD_RETURN_RESPONSE in main_content:
        main_content = main_content.replace(OLD_RETURN_RESPONSE, NEW_RETURN_RESPONSE)
        print("Fail email fire injected into submit_test: YES")
    else:
        print("WARNING: Could not find submit_test await update_user block — manual check needed")

# 2c. Fix /api/certification/retake-payment to also add /api/onboarding/retake-payment
# Add new onboarding endpoints after the existing admin confirm-retake endpoint

ONBOARDING_RETAKE_ENDPOINTS = '''

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
'''

if '/api/onboarding/retake-payment/verify' in main_content:
    print("onboarding retake-payment endpoints already exist")
else:
    # Insert before the chatbot section (which is after admin confirm-retake)
    CHATBOT_MARKER = '# Chat session store:'
    if CHATBOT_MARKER in main_content:
        main_content = main_content.replace(CHATBOT_MARKER, ONBOARDING_RETAKE_ENDPOINTS + '\n' + CHATBOT_MARKER)
        print("onboarding retake-payment endpoints added: YES")
    else:
        # Append at end before last lines
        main_content = main_content.rstrip() + '\n' + ONBOARDING_RETAKE_ENDPOINTS + '\n'
        print("onboarding retake-payment endpoints appended at end: YES")

open(MAIN_PATH, 'w', encoding='utf-8').write(main_content)
print("main.py saved. Size:", len(main_content))
