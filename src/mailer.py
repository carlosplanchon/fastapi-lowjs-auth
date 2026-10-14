import logging
import smtplib
import ssl
from asyncio import sleep, to_thread
from email.message import EmailMessage

from shared import EMAIL_SETTINGS

logger = logging.getLogger(__name__)

EMAIL_BACKEND = EMAIL_SETTINGS["BACKEND"]
SMTP_SECURITY = EMAIL_SETTINGS.get("SMTP_SECURITY", "starttls")

if EMAIL_BACKEND not in ("console", "smtp"):
    raise ValueError(f'[email] BACKEND must be "console" or "smtp", not {EMAIL_BACKEND!r}')
if SMTP_SECURITY not in ("starttls", "ssl", "none"):
    raise ValueError(f'[email] SMTP_SECURITY must be "starttls", "ssl" or "none", not {SMTP_SECURITY!r}')

RETRY_DELAYS_SECONDS = (2, 10)


async def send_email(to: str, subject: str, body: str) -> None:
    """Send a plain-text email. Runs as a background task, after the response."""
    if EMAIL_BACKEND == "console":
        logger.warning("Email not sent (console backend)\nTo: %s\nSubject: %s\n\n%s", to, subject, body)
        return

    message = EmailMessage()
    message["From"] = EMAIL_SETTINGS["FROM_ADDRESS"]
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)

    for attempt, delay in enumerate((*RETRY_DELAYS_SECONDS, None), start=1):
        try:
            # smtplib blocks: in a thread, so the app keeps answering meanwhile.
            await to_thread(deliver, message)
            return
        except OSError as error:  # connection problems, and the server's refusals
            if delay is None or not is_temporary(error):
                logger.exception("Email %r to %s not sent (attempt %d)", subject, to, attempt)
                return
            logger.warning("Email %r to %s failed (%s), trying again in %d s", subject, to, error, delay)
        await sleep(delay)


def is_temporary(error: OSError) -> bool:
    """Whether the same email may get through in a few seconds."""
    if isinstance(error, smtplib.SMTPResponseException):
        # 4xx: try again later. 5xx: refused for good (a wrong password, a bad address...).
        return 400 <= error.smtp_code < 500
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        return all(400 <= code < 500 for code, _ in error.recipients.values())
    if isinstance(error, smtplib.SMTPServerDisconnected):
        return True
    # A feature the server lacks, or a TLS problem, is in the settings. The rest (no
    # connection, a timeout, a failed lookup) may well pass.
    return not isinstance(error, (smtplib.SMTPException, ssl.SSLError))


def deliver(message: EmailMessage) -> None:
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
