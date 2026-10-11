import re
from urllib.parse import parse_qs, urlsplit

from fastapi_sso.sso.base import OpenID


def fake_google_account(monkeypatch, app_module, email):
    async def get_discovery_document():
        return {"authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth"}

    async def verify_and_process(request, **kwargs):
        return OpenID(email=email, provider="google", id="google-account-id")

    monkeypatch.setattr(app_module.google_sso, "get_discovery_document", get_discovery_document)
    monkeypatch.setattr(app_module.google_sso, "verify_and_process", verify_and_process)


def start_google_login(client, prefix):
    """Hit /auth/google/login and return the state it sends to Google."""
    response = client.get(f"{prefix}/auth/google/login", follow_redirects=False)
    assert response.status_code == 303
    return parse_qs(urlsplit(response.headers["location"]).query)["state"][0]


def google_login(client, prefix):
    state = start_google_login(client, prefix)
    response = client.get(
        f"{prefix}/auth/google/callback",
        params={"code": "test", "state": state},
        follow_redirects=False,
    )
    assert response.status_code == 307
    # The state is single use, and the token travels in the fragment.
    assert "google_oauth_state" not in client.cookies
    location = response.headers["location"]
    assert location.startswith(f"{prefix}/login#token=")
    return location.split("#token=", 1)[1]


def get_me(client, prefix, token):
    return client.get(f"{prefix}/me", headers={"Authorization": f"Bearer {token}"})


def get_user(client, prefix, token):
    return client.get(f"{prefix}/users/me", headers={"Authorization": f"Bearer {token}"})


def test_login_page_renders(client, prefix):
    assert client.get(f"{prefix}/login").status_code == 200


def test_login_page_serves_its_css_and_js_locally(client, prefix):
    html = client.get(f"{prefix}/login").text
    # No development CDNs: every stylesheet and script comes from /static.
    urls = re.findall(r'<(?:link|script)[^>]* (?:href|src)="([^"]+)"', html)
    assert urls
    for url in urls:
        assert url.startswith(f"http://testserver{prefix}/static/")
        response = client.get(url)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(("text/css", "text/javascript"))


def test_password_register_and_login(client, prefix):
    response = client.post(
        f"{prefix}/auth/register",
        json={"email": "ana@example.com", "password": "long-secret"},
    )
    assert response.status_code == 201

    # Sent as a form, like login.html does: fastapi-users rejects JSON here.
    response = client.post(
        f"{prefix}/auth/jwt/login",
        data={"username": "ana@example.com", "password": "long-secret"},
    )
    assert response.status_code == 200

    response = get_me(client, prefix, response.json()["access_token"])
    assert response.status_code == 200
    assert response.json()["email"] == "ana@example.com"


def test_register_enforces_min_password_length(client, prefix):
    response = client.post(
        f"{prefix}/auth/register",
        json={"email": "ana@example.com", "password": "1234567"},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "REGISTER_INVALID_PASSWORD"

    response = client.post(
        f"{prefix}/auth/register",
        json={"email": "ana@example.com", "password": "12345678"},
    )
    assert response.status_code == 201


def test_google_login_creates_user(client, prefix, app_module, monkeypatch):
    fake_google_account(monkeypatch, app_module, "new@gmail.com")
    token = google_login(client, prefix)

    response = get_me(client, prefix, token)
    assert response.status_code == 200
    assert response.json()["email"] == "new@gmail.com"
    assert get_user(client, prefix, token).json()["is_verified"] is True


def test_google_login_existing_user(client, prefix, app_module, monkeypatch):
    fake_google_account(monkeypatch, app_module, "back@gmail.com")

    first = get_me(client, prefix, google_login(client, prefix))
    assert first.status_code == 200

    second = get_me(client, prefix, google_login(client, prefix))
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]


def test_google_login_takes_over_unverified_account(client, prefix, app_module, monkeypatch):
    # Someone registers the email with a password first: it may be an attacker.
    response = client.post(
        f"{prefix}/auth/register",
        json={"email": "ana@gmail.com", "password": "long-secret"},
    )
    assert response.status_code == 201

    fake_google_account(monkeypatch, app_module, "ana@gmail.com")
    response = get_user(client, prefix, google_login(client, prefix))
    assert response.status_code == 200
    assert response.json()["is_verified"] is True

    # Google wins: the password set before no longer works.
    response = client.post(
        f"{prefix}/auth/jwt/login",
        data={"username": "ana@gmail.com", "password": "long-secret"},
    )
    assert response.status_code == 400


def test_google_callback_rejects_bad_state(client, prefix, app_module, monkeypatch):
    async def verify_and_process(request, **kwargs):
        raise AssertionError("the code must not be exchanged without a valid state")

    fake_google_account(monkeypatch, app_module, "new@gmail.com")
    monkeypatch.setattr(app_module.google_sso, "verify_and_process", verify_and_process)
    callback = f"{prefix}/auth/google/callback"

    # No state cookie: a login this browser never started (login CSRF).
    assert client.get(callback, params={"code": "test", "state": "forged"}).status_code == 400

    # The browser started a login, but the state in the URL isn't the one sent to Google.
    start_google_login(client, prefix)
    assert client.get(callback, params={"code": "test", "state": "forged"}).status_code == 400


def test_google_state_cookie_is_httponly_and_scoped(client, prefix, app_module, monkeypatch):
    fake_google_account(monkeypatch, app_module, "new@gmail.com")

    response = client.get(f"{prefix}/auth/google/login", follow_redirects=False)
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie
    assert f"path={prefix}/auth/google/callback" in cookie
