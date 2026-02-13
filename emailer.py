import os
import smtplib
from email.message import EmailMessage

def send_otp_email(to_email: str, code: str, target: str) -> None:
    host = os.getenv("SMTP_HOST", "").strip()
    port = int((os.getenv("SMTP_PORT", "587").strip() or "587"))
    user = os.getenv("SMTP_USER", "").strip()
    pw = os.getenv("SMTP_PASS", "").strip()
    from_addr = os.getenv("SMTP_FROM", "").strip() or user
    use_tls = os.getenv("SMTP_TLS", "true").strip().lower() in ("1", "true", "yes", "y")

    if not host or not user or not pw or not from_addr:
        raise RuntimeError("smtp_not_configured")

    msg = EmailMessage()
    msg["Subject"] = "Your ACTIVSCAN verification code"
    msg["From"] = from_addr
    msg["To"] = to_email
    msg.set_content(
        f"""Your ACTIVSCAN verification code is: {code}

Target: {target}

This code expires in 10 minutes. If you didn't request this email, you can ignore it.
"""
    )

    with smtplib.SMTP(host, port, timeout=15) as s:
        if use_tls:
            s.starttls()
        s.login(user, pw)
        s.send_message(msg)
