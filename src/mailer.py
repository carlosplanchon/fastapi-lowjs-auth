import logging
import smtplib
import ssl
from email.message import EmailMessage

from shared import EMAIL_SETTINGS

logger = logging.getLogger(__name__)

EMAIL_BACKEND = EMAIL_SETTINGS["BACKEND"]
SMTP_SECURITY = EMAIL_SETTINGS.get("SMTP_SECURITY", "starttls")

if EMAIL_BACKEND not in ("console", "smtp"):
    raise ValueError(f'[email] BACKEND must be "console" or "smtp", not {EMAIL_BACKEND!r}')
if SMTP_SECURITY not in ("starttls", "ssl", "none"):
    raise ValueError(f'[email] SMTP_SECURITY must be "starttls", "ssl" or "none", not {SMTP_SECURITY!r}')


def send_email(to: str, subject: str, body: str) -> None:
    """Send a plain-text email. Runs as a background task, after the response."""
    if EMAIL_BACKEND == "console":
        logger.warning("Email not sent (console backend)\nTo: %s\nSubject: %s\n\n%s", to, subject, body)
        return

    message = EmailMessage()
    message["From"] = EMAIL_SETTINGS["FROM_ADDRESS"]
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)

    host, port = EMAIL_SETTINGS["SMTP_HOST"], EMAIL_SETTINGS["SMTP_PORT"]
    context = ssl.create_default_context()
    if SMTP_SECURITY == "ssl":
        smtp = smtplib.SMTP_SSL(host, port, timeout=10, context=context)
    else:
        smtp = smtplib.SMTP(host, port, timeout=10)
    with smtp:
        if SMTP_SECURITY == "starttls":
            smtp.starttls(context=context)
        if EMAIL_SETTINGS.get("SMTP_USERNAME"):
            smtp.login(EMAIL_SETTINGS["SMTP_USERNAME"], EMAIL_SETTINGS["SMTP_PASSWORD"])
        smtp.send_message(message)
