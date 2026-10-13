import re

from fastapi_users.db import SQLAlchemyUserDatabase
from sqlalchemy import update

from models import User


def register(client, prefix, email="ana@example.com", password="long-secret"):
    response = client.post(f"{prefix}/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201


def sign_in(client, prefix, email="ana@example.com", password="long-secret"):
    return client.post(f"{prefix}/auth/cookie/login", data={"username": email, "password": password})


def jwt_sign_in(client, prefix, email, password="long-secret"):
    return client.post(f"{prefix}/auth/jwt/login", data={"username": email, "password": password})


def request_change(client, prefix, new_email="ana@new.example", password="long-secret", **kwargs):
    return client.post(
        f"{prefix}/auth/request-email-change",
        json={"new_email": new_email, "password": password},
        **kwargs,
    )


def approve(client, prefix, token, **kwargs):
    return client.post(f"{prefix}/auth/approve-email-change", json={"token": token}, **kwargs)


def confirm(client, prefix, token, **kwargs):
    return client.post(f"{prefix}/auth/confirm-email-change", json={"token": token}, **kwargs)


def link_in(email, name):
    """Return the (url, token) of the "#name=token" link in an email's body."""
    _, _, body = email
    return re.search(rf"(\S+)#{name}=(\S+)", body).groups()


def run_in_app(client, app_module, statement):
    """Run a SQL statement on the app's database, on the app's event loop."""

    async def run():
        async with app_module.database.async_session_maker() as session:
            await session.execute(statement)
            await session.commit()

    client.portal.call(run)


def test_changing_the_email(client, prefix, app_module, sent_emails):
    register(client, prefix)
    run_in_app(client, app_module, update(User).values(is_verified=True))
    sign_in(client, prefix)
    sent_emails.clear()

    # First the current address approves. A forged Host must not end up in the link.
    response = request_change(client, prefix, headers={"host": "evil.example"})
    assert response.status_code == 202
    [approval] = sent_emails
    assert approval[:2] == ("ana@example.com", "Approve your new email")
    assert "ana@new.example" in approval[2]
    url, approve_token = link_in(approval, "approve_email_token")
    assert url == f"https://auth.example{prefix}/login"

    # Then the new address confirms.
    sent_emails.clear()
    response = approve(client, prefix, approve_token)
    assert (response.status_code, response.json()) == (200, {"email": "ana@new.example"})
    [confirmation] = sent_emails
    assert confirmation[:2] == ("ana@new.example", "Confirm your new email")
    assert "ana@example.com" not in confirmation[2]
    # The requester picks this address: its owner is told not to confirm.
    assert "If you didn't ask for this, ignore this email" in confirmation[2]
    url, confirm_token = link_in(confirmation, "confirm_email_token")
    assert url == f"https://auth.example{prefix}/login"

    sent_emails.clear()
    response = confirm(client, prefix, confirm_token)
    assert (response.status_code, response.json()) == (200, {"email": "ana@new.example"})
    # The old address, which approved it, gets the news.
    assert [(to, subject) for to, subject, _ in sent_emails] == [("ana@example.com", "Your email was changed")]

    # Same session, new email, verified by the link.
    me = client.get(f"{prefix}/me").json()
    assert (me["email"], me["is_verified"]) == ("ana@new.example", True)
    assert jwt_sign_in(client, prefix, "ana@new.example").status_code == 200
    assert jwt_sign_in(client, prefix, "ana@example.com").status_code == 400


def test_unverified_accounts_also_need_their_current_address_to_approve(client, prefix, sent_emails):
    # Otherwise anyone with the password could move the account with no one noticing.
    register(client, prefix)
    sign_in(client, prefix)
    sent_emails.clear()

    assert request_change(client, prefix).status_code == 202
    assert [(to, subject) for to, subject, _ in sent_emails] == [("ana@example.com", "Approve your new email")]

    # Once the new address confirms, the account is verified.
    _, approve_token = link_in(sent_emails[-1], "approve_email_token")
    approve(client, prefix, approve_token)
    _, confirm_token = link_in(sent_emails[-1], "confirm_email_token")
    assert confirm(client, prefix, confirm_token).status_code == 200
    assert client.get(f"{prefix}/me").json()["is_verified"] is True


def test_requests_that_change_nothing(client, prefix, sent_emails):
    register(client, prefix)
    register(client, prefix, email="bob@example.com")
    sign_in(client, prefix)
    sent_emails.clear()

    response = request_change(client, prefix, password="not-my-password")
    assert (response.status_code, response.json()["detail"]) == (400, "CHANGE_EMAIL_BAD_CREDENTIALS")
    response = request_change(client, prefix, new_email="ANA@example.com")
    assert (response.status_code, response.json()["detail"]) == (400, "CHANGE_EMAIL_SAME_EMAIL")
    response = request_change(client, prefix, new_email="Bob@Example.com")
    assert (response.status_code, response.json()["detail"]) == (400, "CHANGE_EMAIL_ALREADY_EXISTS")
    assert request_change(client, prefix, new_email="not-an-email").status_code == 422
    assert sent_emails == []


def test_links_work_once_and_only_for_their_step(client, prefix, sent_emails):
    register(client, prefix)
    sign_in(client, prefix)
    request_change(client, prefix)
    _, approve_token = link_in(sent_emails[-1], "approve_email_token")

    # An approval link can't confirm: the new address hasn't agreed yet.
    assert confirm(client, prefix, approve_token).json()["detail"] == "CHANGE_EMAIL_BAD_TOKEN"
    assert approve(client, prefix, approve_token).status_code == 200
    _, confirm_token = link_in(sent_emails[-1], "confirm_email_token")
    assert approve(client, prefix, confirm_token).json()["detail"] == "CHANGE_EMAIL_BAD_TOKEN"
    assert confirm(client, prefix, "not-a-token").json()["detail"] == "CHANGE_EMAIL_BAD_TOKEN"

    assert confirm(client, prefix, confirm_token).status_code == 200
    # Once the email changed, neither link applies anymore.
    assert confirm(client, prefix, confirm_token).json()["detail"] == "CHANGE_EMAIL_BAD_TOKEN"
    assert approve(client, prefix, approve_token).json()["detail"] == "CHANGE_EMAIL_BAD_TOKEN"


def test_a_password_change_cancels_pending_changes(client, prefix, sent_emails):
    register(client, prefix)
    sign_in(client, prefix)
    request_change(client, prefix)
    _, approve_token = link_in(sent_emails[-1], "approve_email_token")

    response = client.post(
        f"{prefix}/auth/change-password",
        json={"current_password": "long-secret", "new_password": "new-long-secret"},
    )
    assert response.status_code == 204
    assert approve(client, prefix, approve_token).json()["detail"] == "CHANGE_EMAIL_BAD_TOKEN"


def test_an_address_taken_in_between(client, prefix, sent_emails):
    register(client, prefix)
    sign_in(client, prefix)
    request_change(client, prefix)
    _, approve_token = link_in(sent_emails[-1], "approve_email_token")
    approve(client, prefix, approve_token)
    _, confirm_token = link_in(sent_emails[-1], "confirm_email_token")
    register(client, prefix, email="ana@new.example")

    assert approve(client, prefix, approve_token).json()["detail"] == "CHANGE_EMAIL_ALREADY_EXISTS"
    response = confirm(client, prefix, confirm_token)
    assert (response.status_code, response.json()["detail"]) == (400, "CHANGE_EMAIL_ALREADY_EXISTS")
    assert client.get(f"{prefix}/me").json()["email"] == "ana@example.com"


def test_a_race_for_the_address_is_a_400_not_a_500(client, prefix, sent_emails, monkeypatch):
    # Someone signs up with the address between the check and the update: the
    # database's unique index catches it.
    register(client, prefix)
    sign_in(client, prefix)
    request_change(client, prefix)
    _, approve_token = link_in(sent_emails[-1], "approve_email_token")
    approve(client, prefix, approve_token)
    _, confirm_token = link_in(sent_emails[-1], "confirm_email_token")
    register(client, prefix, email="ana@new.example")

    async def nobody(self, email):
        return None

    monkeypatch.setattr(SQLAlchemyUserDatabase, "get_by_email", nobody)
    response = confirm(client, prefix, confirm_token)
    assert (response.status_code, response.json()["detail"]) == (400, "CHANGE_EMAIL_ALREADY_EXISTS")
    assert client.get(f"{prefix}/me").json()["email"] == "ana@example.com"


def test_it_needs_a_session_and_requests_from_this_site(client, prefix):
    register(client, prefix)
    assert request_change(client, prefix).status_code == 401

    sign_in(client, prefix)
    evil = {"Origin": "https://evil.example"}
    assert request_change(client, prefix, headers=evil).status_code == 403
    assert approve(client, prefix, "any", headers=evil).status_code == 403
    assert confirm(client, prefix, "any", headers=evil).status_code == 403
