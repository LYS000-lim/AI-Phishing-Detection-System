"""
Minimal outbound email helper.

FYP scope: real SMTP delivery is opt-in via env vars (PHISHGUARD_SMTP_*).
Without those configured, reset links are logged to the backend console
instead - this is documented in the report as a deployment-dependent
limitation, not a stand-in security weakness (the link is never returned
in the API response, only printed server-side).
"""
import logging
import os
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger("phishguard.email")

SMTP_HOST = os.environ.get("PHISHGUARD_SMTP_HOST")
SMTP_PORT = int(os.environ.get("PHISHGUARD_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("PHISHGUARD_SMTP_USER")
SMTP_PASSWORD = os.environ.get("PHISHGUARD_SMTP_PASSWORD")
SMTP_FROM = os.environ.get("PHISHGUARD_SMTP_FROM", SMTP_USER or "no-reply@phishguard.local")


def send_password_reset_email(to_email: str, reset_link: str) -> None:
    subject = "PhishGuard AI - Password Reset Request"
    body = (
        "We received a request to reset your PhishGuard AI password.\n\n"
        f"Reset your password: {reset_link}\n\n"
        "This link expires in 30 minutes. If you did not request this, "
        "you can safely ignore this email."
    )

    if not SMTP_HOST:
        logger.warning(
            "PHISHGUARD_SMTP_HOST not configured - dev mode. "
            "Password reset link for %s: %s", to_email, reset_link,
        )
        return

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD or "")
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
    except Exception:
        # Never let an email-delivery failure block the reset flow or leak
        # to the client - fall back to the console link like dev mode.
        logger.exception(
            "Failed to send password reset email to %s - link: %s",
            to_email, reset_link,
        )
