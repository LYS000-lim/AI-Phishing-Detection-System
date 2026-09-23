"""
Minimal outbound email helper (password-reset verification codes).

Real delivery is via SMTP, configured in backend/.env (see .env.example).
For Gmail: PHISHGUARD_SMTP_HOST=smtp.gmail.com, port 587, the Gmail
address as user, and a 16-character Google *App Password* (Google Account
-> Security -> 2-Step Verification -> App passwords) as the password - a
normal Gmail password is rejected by Google's SMTP server.

Without SMTP configured (or if sending fails), the code is logged to the
backend console instead - it is never returned in the API response.
"""
import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger("phishguard.email")

SMTP_HOST = os.environ.get("PHISHGUARD_SMTP_HOST")
SMTP_PORT = int(os.environ.get("PHISHGUARD_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("PHISHGUARD_SMTP_USER")
SMTP_PASSWORD = os.environ.get("PHISHGUARD_SMTP_PASSWORD")
SMTP_FROM = os.environ.get("PHISHGUARD_SMTP_FROM", SMTP_USER or "no-reply@phishguard.local")


def send_password_reset_code(to_email: str, code: str, ttl_minutes: int) -> None:
    subject = "PhishGuard AI - Your password reset code"
    text = (
        "We received a request to reset your PhishGuard AI password.\n\n"
        f"Your verification code is: {code}\n\n"
        f"This code expires in {ttl_minutes} minutes. If you did not request "
        "this, you can safely ignore this email - your password won't change."
    )
    html = (
        '<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;color:#1f2937">'
        '<h2 style="color:#0ea5e9;margin-bottom:4px">PhishGuard AI</h2>'
        "<p>We received a request to reset your password. Enter this code on the reset page:</p>"
        '<p style="font-size:32px;font-weight:bold;letter-spacing:8px;background:#f1f5f9;'
        f'padding:14px;text-align:center;border-radius:8px">{code}</p>'
        f"<p>This code expires in <b>{ttl_minutes} minutes</b>.</p>"
        '<p style="color:#6b7280;font-size:13px">If you did not request this, you can safely '
        "ignore this email - your password won't change. PhishGuard will never ask you for "
        "this code by phone or chat.</p></div>"
    )

    if not SMTP_HOST:
        logger.warning(
            "PHISHGUARD_SMTP_HOST not configured - dev mode. "
            "Password reset code for %s: %s", to_email, code,
        )
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD or "")
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
    except Exception:
        # Never let an email-delivery failure block the flow or leak to the
        # client - fall back to logging the code like dev mode.
        logger.exception(
            "Failed to send password reset code to %s - code: %s", to_email, code,
        )
