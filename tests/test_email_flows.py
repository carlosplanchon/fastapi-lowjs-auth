import re

from fastapi.testclient import TestClient


def register(client, prefix, email="ana@example.com", password="long-secret"):
    response = client.post(f"{prefix}/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201


def sign_in(client, prefix, email="ana@example.com", password="long-secret"):
    return client.post(f"{prefix}/auth/jwt/login", data={"username": email, "password": password})


def me(client, prefix, password="long-secret"):
    token = sign_in(client, prefix, password=password).json()["access_token"]
    return client.get(f"{prefix}/me", headers={"Authorization": f"Bearer {token}"}).json()


def link_in(email, name):
    """Return the (url, token) of the "#name=token" link in an email's body."""
    _, _, body = email
    return re.search(rf"(\S+)#{name}=(\S+)", body).groups()


def change_password(client, prefix, current="long-secret", new="new-long-secret", headers=None):
    token = sign_in(client, prefix).json()["access_token"]
    return client.post(
        f"{prefix}/auth/change-password",
        json={"current_password": current, "new_password": new},
        headers={"Authorization": f"Bearer {token}", **(headers or {})},
    )


def request_reset(client, prefix, sent_emails, **kwargs):
    response = client.post(f"{prefix}/auth/forgot-password", json={"email": "ana@example.com"}, **kwargs)
    assert response.status_code == 202
    return sent_emails[-1]


def test_registration_sends_a_verification_link(client, prefix, sent_emails):
    register(client, prefix)

    [email] = sent_emails
    assert email[:2] == ("ana@example.com", "Verify your email")
    # Anyone can sign up someone else's address: its owner is told not to confirm.
    assert "If you didn't sign up, ignore this email" in email[2]
    url, token = link_in(email, "verify_token")
    assert url == f"https://auth.example{prefix}/login"

    assert me(client, prefix)["is_verified"] is False
    assert client.post(f"{prefix}/auth/verify", json={"token": token}).status_code == 200
    assert me(client, prefix)["is_verified"] is True


def test_verification_link_can_be_requested_again(client, prefix, sent_emails):
    register(client, prefix)

    response = client.post(f"{prefix}/auth/request-verify-token", json={"email": "ana@example.com"})
    assert response.status_code == 202
    assert [subject for _, subject, _ in sent_emails] == ["Verify your email"] * 2
    _, token = link_in(sent_emails[-1], "verify_token")
    assert client.post(f"{prefix}/auth/verify", json={"token": token}).status_code == 200


def test_forgot_password_resets_with_the_emailed_link(client, prefix, sent_emails):
    register(client, prefix)
    email = request_reset(client, prefix, sent_emails)
    assert email[:2] == ("ana@example.com", "Reset your password")
    _, token = link_in(email, "reset_token")

    response = client.post(f"{prefix}/auth/reset-password", json={"token": token, "password": "new-long-secret"})
    assert response.status_code == 200
    assert sign_in(client, prefix, password="new-long-secret").status_code == 200
    assert sign_in(client, prefix).status_code == 400

    # The link stops working once the password changed.
    response = client.post(f"{prefix}/auth/reset-password", json={"token": token, "password": "other-secret"})
    assert response.json()["detail"] == "RESET_PASSWORD_BAD_TOKEN"


def test_email_failures_happen_after_the_response(app_module, prefix, monkeypatch):
    def send_email(*email):
        raise ConnectionRefusedError("SMTP server is down")

    monkeypatch.setattr(app_module.users.mailer, "send_email", send_email)
    # Emails go out in background tasks: if sending fails, the answer is still the
    # same one an unknown email gets, so it can't reveal which accounts exist.
    with TestClient(app_module.app, raise_server_exceptions=False) as client:
        register(client, prefix)
        response = client.post(f"{prefix}/auth/forgot-password", json={"email": "ana@example.com"})
        assert response.status_code == 202


def test_forgot_password_for_an_unknown_email_sends_nothing(client, prefix, sent_emails):
    response = client.post(f"{prefix}/auth/forgot-password", json={"email": "nobody@example.com"})
    assert response.status_code == 202
    assert sent_emails == []


def test_email_links_ignore_the_request_host_header(client, prefix, sent_emails):
    register(client, prefix)
    # A forged Host must not end up in the link: it would send the token elsewhere.
    email = request_reset(client, prefix, sent_emails, headers={"host": "evil.example"})
    url, _ = link_in(email, "reset_token")
    assert url == f"https://auth.example{prefix}/login"


def test_password_reset_verifies_the_account(client, prefix, sent_emails):
    register(client, prefix)
    _, token = link_in(request_reset(client, prefix, sent_emails), "reset_token")

    client.post(f"{prefix}/auth/reset-password", json={"token": token, "password": "new-long-secret"})
    assert me(client, prefix, password="new-long-secret")["is_verified"] is True


def test_reset_password_enforces_min_password_length(client, prefix, sent_emails):
    register(client, prefix)
    _, token = link_in(request_reset(client, prefix, sent_emails), "reset_token")

    response = client.post(f"{prefix}/auth/reset-password", json={"token": token, "password": "1234567"})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "RESET_PASSWORD_INVALID_PASSWORD"


def test_changing_the_password_sends_a_notice(client, prefix, sent_emails):
    register(client, prefix)
    sent_emails.clear()

    # A forged Host must not end up in the link either.
    assert change_password(client, prefix, headers={"host": "evil.example"}).status_code == 204
    [(to, subject, body)] = sent_emails
    assert (to, subject) == ("ana@example.com", "Your password was changed")
    assert f"https://auth.example{prefix}/login\n" in body
    assert "evil.example" not in body


def test_resetting_the_password_sends_a_notice(client, prefix, sent_emails):
    register(client, prefix)
    _, token = link_in(request_reset(client, prefix, sent_emails), "reset_token")

    client.post(f"{prefix}/auth/reset-password", json={"token": token, "password": "new-long-secret"})
    assert sent_emails[-1][:2] == ("ana@example.com", "Your password was changed")


def test_no_notice_when_the_password_does_not_change(client, prefix, sent_emails):
    register(client, prefix)
    assert change_password(client, prefix, current="wrong-password").status_code == 400
    assert change_password(client, prefix, new="1234567").status_code == 400
    _, token = link_in(request_reset(client, prefix, sent_emails), "reset_token")
    response = client.post(f"{prefix}/auth/reset-password", json={"token": token, "password": "1234567"})
    assert response.status_code == 400

    assert "Your password was changed" not in [subject for _, subject, _ in sent_emails]
