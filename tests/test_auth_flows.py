from fastapi_sso.sso.base import OpenID


def fake_google_account(monkeypatch, app_module, email):
    async def verify_and_process(request, **kwargs):
        return OpenID(email=email, provider="google", id="google-account-id")

    monkeypatch.setattr(app_module.google_sso, "verify_and_process", verify_and_process)


def google_login(client, prefix):
    response = client.get(f"{prefix}/auth/google/callback?code=test", follow_redirects=False)
    assert response.status_code == 307
    location = response.headers["location"]
    assert location.startswith(f"{prefix}/login?token=")
    return location.split("token=", 1)[1]


def get_me(client, prefix, token):
    return client.get(f"{prefix}/me", headers={"Authorization": f"Bearer {token}"})


def test_login_page_renders(client, prefix):
    assert client.get(f"{prefix}/login").status_code == 200


def test_password_register_and_login(client, prefix):
    response = client.post(
        f"{prefix}/auth/register",
        json={"email": "ana@example.com", "password": "secret"},
    )
    assert response.status_code == 201

    # Sent as a form, like login.html does: fastapi-users rejects JSON here.
    response = client.post(
        f"{prefix}/auth/jwt/login",
        data={"username": "ana@example.com", "password": "secret"},
    )
    assert response.status_code == 200

    response = get_me(client, prefix, response.json()["access_token"])
    assert response.status_code == 200
    assert response.json()["email"] == "ana@example.com"


def test_google_login_creates_user(client, prefix, app_module, monkeypatch):
    fake_google_account(monkeypatch, app_module, "new@gmail.com")

    response = get_me(client, prefix, google_login(client, prefix))
    assert response.status_code == 200
    assert response.json()["email"] == "new@gmail.com"


def test_google_login_existing_user(client, prefix, app_module, monkeypatch):
    fake_google_account(monkeypatch, app_module, "back@gmail.com")

    first = get_me(client, prefix, google_login(client, prefix))
    assert first.status_code == 200

    second = get_me(client, prefix, google_login(client, prefix))
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]
