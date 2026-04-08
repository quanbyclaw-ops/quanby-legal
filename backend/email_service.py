"""
email_service.py — Quanby Legal Email Sending Service
Uses Python's built-in smtplib + email libraries with Gmail SMTP.
Credentials loaded from .env: EMAIL_FROM, EMAIL_PASSWORD
"""

import os
import smtplib
import logging
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

# ── Config ──────────────────────────────────────────────────────────────────
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_FROM     = os.getenv("EMAIL_FROM", "noreply@quanby.legal")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")


def send_email(to_email: str, subject: str, html_body: str, text_body: str = "") -> bool:
    """
    Send an email via Gmail SMTP with STARTTLS.
    Returns True on success, False on failure (fails gracefully — never raises).
    """
    if not EMAIL_PASSWORD:
        logger.warning(
            "[email_service] EMAIL_PASSWORD not set — skipping email to %s", to_email
        )
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"Quanby Legal <{EMAIL_FROM}>"
        msg["To"]      = to_email

        if text_body:
            msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.sendmail(EMAIL_FROM, [to_email], msg.as_string())

        logger.info("[email_service] Email sent to %s — subject: %s", to_email, subject)
        return True

    except Exception as exc:
        logger.warning("[email_service] Failed to send email to %s: %s", to_email, exc)
        return False


def _build_welcome_html(first_name: str, last_name: str) -> str:
    """Generate HTML welcome email with Quanby Legal navy/gold branding."""
    full_name = f"{first_name} {last_name}".strip() or "Attorney"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Welcome to Quanby Legal</title>
</head>
<body style="margin:0;padding:0;background:#f4f6fb;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6fb;padding:40px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

        <!-- Header -->
        <tr>
          <td style="background:linear-gradient(135deg,#0d1b3e 0%,#1a2f5e 100%);padding:36px 40px;text-align:center;">
            <div style="display:inline-block;background:#c9a227;border-radius:50%;width:52px;height:52px;line-height:52px;text-align:center;font-size:1.5rem;font-weight:700;color:#0d1b3e;margin-bottom:12px;">QL</div>
            <h1 style="color:#ffffff;margin:0;font-size:1.5rem;font-weight:700;letter-spacing:-0.5px;">Quanby Legal Platform</h1>
            <p style="color:#c9a227;margin:6px 0 0;font-size:0.875rem;letter-spacing:1px;text-transform:uppercase;">Supreme Court-Accredited ENF</p>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:40px 40px 32px;">
            <h2 style="color:#0d1b3e;margin:0 0 16px;font-size:1.25rem;">Hello {full_name},</h2>
            <p style="color:#374151;line-height:1.7;margin:0 0 20px;">
              Welcome to the <strong>Quanby Legal Platform</strong> — the Philippines' first
              Supreme Court-accredited electronic notarization facility.
            </p>
            <p style="color:#374151;line-height:1.7;margin:0 0 24px;">
              Please complete the following steps to finish your onboarding process:
            </p>

            <!-- Steps -->
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="padding:12px 16px;background:#f8f7ff;border-left:4px solid #c9a227;border-radius:4px;margin-bottom:12px;">
                  <strong style="color:#0d1b3e;">Step 1.</strong>
                  <span style="color:#374151;"> Take the course module and complete the exam.</span><br>
                  <a href="https://legal.quanbyai.com/mastering-quanby-legal.pdf" style="color:#c9a227;font-size:0.9rem;">&#128218; Download Course Module (PDF)</a>&nbsp;&nbsp;
                  <a href="https://legal.quanbyai.com/?exam=1" style="display:inline-block;background:#c9a227;color:#0d1b3e;padding:6px 14px;border-radius:4px;text-decoration:none;font-weight:700;font-size:0.85rem;margin-top:8px;">&#127891; Take the Exam</a>
                </td>
              </tr>
              <tr><td style="height:10px;"></td></tr>
              <tr>
                <td style="padding:12px 16px;background:#f8f7ff;border-left:4px solid #c9a227;border-radius:4px;">
                  <strong style="color:#0d1b3e;">Step 2.</strong>
                  <span style="color:#374151;"> Download the course certificate.</span>
                </td>
              </tr>
              <tr><td style="height:10px;"></td></tr>
              <tr>
                <td style="padding:12px 16px;background:#f8f7ff;border-left:4px solid #c9a227;border-radius:4px;">
                  <strong style="color:#0d1b3e;">Step 3.</strong>
                  <span style="color:#374151;"> Submit your certificate online to the Supreme Court.</span>
                </td>
              </tr>
            </table>

            <!-- CTA Button -->
            <div style="text-align:center;margin:36px 0 24px;">
              <a href="https://legal.quanbyai.com/"
                 style="display:inline-block;background:#c9a227;color:#0d1b3e;text-decoration:none;
                        font-weight:700;font-size:1rem;padding:14px 40px;border-radius:8px;
                        letter-spacing:0.3px;">
                Access the Platform &rarr;
              </a>
            </div>

            <p style="color:#6b7280;font-size:0.85rem;line-height:1.6;margin:0;">
              If you have any questions, please contact us at
              <a href="mailto:legal@quanby.legal" style="color:#0d1b3e;font-weight:600;">legal@quanby.legal</a>.
            </p>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#0d1b3e;padding:24px 40px;text-align:center;">
            <p style="color:#94a3b8;font-size:0.8rem;margin:0;">
              &copy; 2025 Quanby Solutions, Inc. &bull;
              <a href="https://legal.quanbyai.com/" style="color:#c9a227;text-decoration:none;">legal.quanbyai.com</a>
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _build_welcome_text(first_name: str, last_name: str) -> str:
    """Plain-text fallback for welcome email."""
    full_name = f"{first_name} {last_name}".strip() or "Attorney"
    return f"""Hello {full_name},

Welcome to the Quanby Legal Platform.

Please complete the following steps to complete your onboarding process:

Step 1. Take the course module and complete the exam.
Download Course Module: https://legal.quanbyai.com/mastering-quanby-legal.pdf
Take the Exam: https://legal.quanbyai.com/?exam=1

Step 2. Download the course certificate.
Step 3. Submit your certificate online to the Supreme Court.

Click on the link below for immediate access:
https://legal.quanbyai.com/

The Quanby Legal Team
"""


def send_welcome_email_sync(user: dict) -> bool:
    """Send welcome email to a new user (synchronous). Returns True on success."""
    to_email   = user.get("email", "")
    first_name = user.get("first_name", "")
    last_name  = user.get("last_name", "")

    if not to_email:
        logger.warning("[email_service] send_welcome_email: no email address for user")
        return False

    subject   = "Welcome to the Quanby Legal Platform"
    html_body = _build_welcome_html(first_name, last_name)
    text_body = _build_welcome_text(first_name, last_name)

    return send_email(to_email, subject, html_body, text_body)


def send_welcome_email(user: dict) -> None:
    """
    Fire-and-forget welcome email.
    Runs in a daemon thread — never blocks the caller.
    Fails gracefully if credentials are missing.
    """
    t = threading.Thread(
        target=send_welcome_email_sync,
        args=(user,),
        daemon=True,
        name=f"welcome-email-{user.get('id', 'unknown')}",
    )
    t.start()
