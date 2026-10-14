import asyncio
import importlib
import smtplib
import ssl

import pytest


def use_fake_smtp_server(monkeypatch, mailer, *failures):
    """Send over SMTP to a fake server: each connection fails with the next of
    `failures`, then they all get through. Returns the emails that got through."""
    pending = list(failures)
    delivered = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            if pending:
                raise pending.pop(0)

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def starttls(self, context):
            pass

        def login(self, username, password):
            pass

        def send_message(self, message):
            delivered.append(message)

    monkeypatch.setattr(mailer, "EMAIL_BACKEND", "smtp")
    monkeypatch.setattr(mailer, "SMTP_SECURITY", "none")
    monkeypatch.setitem(mailer.EMAIL_SETTINGS, "SMTP_HOST", "smtp.example")
    monkeypatch.setitem(mailer.EMAIL_SETTINGS, "SMTP_PORT", 587)
    monkeypatch.setattr(mailer.smtplib, "SMTP", FakeSMTP)
    return delivered


def record_pauses(monkeypatch, mailer):
    """The pauses between attempts, recorded instead of waited."""
    pauses = []

    async def sleep(seconds):
        pauses.append(seconds)

    monkeypatch.setattr(mailer, "sleep", sleep)
    return pauses


@pytest.fixture
def mailer(load_shared):
    load_shared()
    return importlib.import_module("mailer")


def send(mailer):
    asyncio.run(mailer.send_email("ana@example.com", "Reset your password", "The link."))


@pytest.mark.parametrize(
    "failure",
    [
        ConnectionRefusedError("the server is down"),
        TimeoutError("timed out"),
        smtplib.SMTPServerDisconnected("connection unexpectedly closed"),
        smtplib.SMTPConnectError(421, b"too many connections, try again later"),
        smtplib.SMTPRecipientsRefused({"ana@example.com": (450, b"mailbox busy")}),
    ],
    ids=["refused", "timeout", "disconnected", "4xx", "4xx-recipient"],
)
def test_a_failure_that_may_pass_is_retried(mailer, monkeypatch, failure):
    pauses = record_pauses(monkeypatch, mailer)
    delivered = use_fake_smtp_server(monkeypatch, mailer, failure)
    send(mailer)
    assert [message["To"] for message in delivered] == ["ana@example.com"]
    assert pauses == [mailer.RETRY_DELAYS_SECONDS[0]]


@pytest.mark.parametrize(
    "failure",
    [
        smtplib.SMTPAuthenticationError(535, b"bad username or password"),
        smtplib.SMTPRecipientsRefused({"ana@example.com": (550, b"no such user")}),
        ssl.SSLCertVerificationError("certificate verify failed"),
    ],
    ids=["wrong-password", "5xx-recipient", "certificate"],
)
def test_a_refusal_or_a_settings_problem_isnt_retried(mailer, monkeypatch, caplog, failure):
    pauses = record_pauses(monkeypatch, mailer)
    delivered = use_fake_smtp_server(monkeypatch, mailer, failure)
    # Logged, not raised: nothing above a background task would catch it.
    send(mailer)
    assert delivered == []
    assert pauses == []
    assert "not sent (attempt 1)" in caplog.text


def test_it_gives_up_after_the_last_retry(mailer, monkeypatch, caplog):
    pauses = record_pauses(monkeypatch, mailer)
    attempts = len(mailer.RETRY_DELAYS_SECONDS) + 1
    delivered = use_fake_smtp_server(monkeypatch, mailer, *[TimeoutError("timed out") for _ in range(attempts)])
    send(mailer)
    assert delivered == []
    assert pauses == list(mailer.RETRY_DELAYS_SECONDS)
    assert f"not sent (attempt {attempts})" in caplog.text


def test_the_app_retries_an_email_after_the_response(client, prefix, app_module, monkeypatch):
    mailer = app_module.users.mailer
    pauses = record_pauses(monkeypatch, mailer)
    response = client.post(f"{prefix}/auth/register", json={"email": "ana@example.com", "password": "long-secret"})
    assert response.status_code == 201
    delivered = use_fake_smtp_server(monkeypatch, mailer, ConnectionRefusedError("the server is down"))

    # The test client waits for the background task, retries included.
    response = client.post(f"{prefix}/auth/forgot-password", json={"email": "ana@example.com"})
    assert response.status_code == 202
    assert [message["Subject"] for message in delivered] == ["Reset your password"]
    assert pauses == [mailer.RETRY_DELAYS_SECONDS[0]]


def test_emails_go_out_without_holding_a_database_connection(client, prefix, app_module, monkeypatch):
    # Otherwise a slow or unreachable SMTP server would use up the connection pool.
    mailer = app_module.users.mailer
    connections_in_use = []

    def deliver(message):
        connections_in_use.append(app_module.database.engine.pool.checkedout())

    monkeypatch.setattr(mailer, "EMAIL_BACKEND", "smtp")
    monkeypatch.setattr(mailer, "deliver", deliver)
    client.post(f"{prefix}/auth/register", json={"email": "ana@example.com", "password": "long-secret"})
    client.post(f"{prefix}/auth/forgot-password", json={"email": "ana@example.com"})
    assert connections_in_use == [0, 0]
