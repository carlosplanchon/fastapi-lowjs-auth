import re
from urllib.parse import parse_qs, urlsplit

from fastapi_sso.sso.base import OpenID, SSOLoginError


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
    """Sign in with the simulated Google; the session cookie stays in the client."""
    state = start_google_login(client, prefix)
    response = client.get(
        f"{prefix}/auth/google/callback",
        params={"code": "test", "state": state},
        follow_redirects=False,
    )
    assert response.status_code == 307
    # Back to the sign-in page with the session in a cookie, not in the URL.
    assert response.headers["location"] == f"{prefix}/login"
    assert "session" in client.cookies
    # The state is single use.
    assert "google_oauth_state" not in client.cookies


def bearer(token):
    return {"Authorization": f"Bearer {token}"} if token else {}


def get_me(client, prefix, token=None):
    """GET /me with a Bearer token, or with the session cookie when there's none."""
    return client.get(f"{prefix}/me", headers=bearer(token))


def get_user(client, prefix, token=None):
    return client.get(f"{prefix}/users/me", headers=bearer(token))


def test_login_page_renders(client, prefix):
    assert client.get(f"{prefix}/login").status_code == 200


def test_login_page_inputs_work_with_screen_readers_and_password_managers(client, prefix):
    html = client.get(f"{prefix}/login").text
    assert '<html lang="en"' in html
    inputs = re.findall(r"<input\b[^>]*>", html)
    assert inputs
    for tag in inputs:
        assert "aria-label=" in tag
        assert "autocomplete=" in tag


def test_login_page_serves_its_css_js_and_images_locally(client, prefix):
    html = client.get(f"{prefix}/login").text
    # Nothing from other sites (the CSP would block it): everything comes from /static.
    urls = re.findall(r'<(?:link|script|img)[^>]* (?:href|src)="([^"]+)"', html)
    assert len(urls) == 5  # the stylesheet, the icon, app.js, Alpine and the Google logo
    for url in urls:
        assert url.startswith(f"{str(client.base_url).rstrip('/')}{prefix}/static/")
        response = client.get(url)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(("text/css", "text/javascript", "image/svg+xml"))
        # Browsers must check with the server before reusing them: a cached app.js
        # could be older than the page.
        assert response.headers["cache-control"] == "no-cache"
        assert client.get(url, headers={"If-None-Match": response.headers["etag"]}).status_code == 304


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
    google_login(client, prefix)

    response = get_me(client, prefix)
    assert response.status_code == 200
    assert response.json()["email"] == "new@gmail.com"
    assert get_user(client, prefix).json()["is_verified"] is True


def test_google_login_existing_user(client, prefix, app_module, monkeypatch):
    fake_google_account(monkeypatch, app_module, "back@gmail.com")

    google_login(client, prefix)
    first = get_me(client, prefix)
    assert first.status_code == 200

    google_login(client, prefix)
    second = get_me(client, prefix)
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]


def test_google_login_takes_over_unverified_account(client, prefix, app_module, monkeypatch):
    # Someone registers the email with a password first: it may be an attacker.
    response = client.post(
        f"{prefix}/auth/register",
        json={"email": "ana@gmail.com", "password": "long-secret"},
    )
    assert response.status_code == 201
    squatter_token = client.post(
        f"{prefix}/auth/jwt/login",
        data={"username": "ana@gmail.com", "password": "long-secret"},
    ).json()["access_token"]

    fake_google_account(monkeypatch, app_module, "ana@gmail.com")
    google_login(client, prefix)
    response = get_user(client, prefix)
    assert response.status_code == 200
    assert response.json()["is_verified"] is True

    # Google wins: the password set before no longer works...
    response = client.post(
        f"{prefix}/auth/jwt/login",
        data={"username": "ana@gmail.com", "password": "long-secret"},
    )
    assert response.status_code == 400
    # ...and neither do the tokens it got (only the token: no session cookie).
    response = client.get(f"{prefix}/me", headers={"Authorization": f"Bearer {squatter_token}", "Cookie": ""})
    assert response.status_code == 401


def test_google_login_keeps_the_password_of_a_verified_account(
    client, prefix, app_module, monkeypatch, sent_emails
):
    response = client.post(
        f"{prefix}/auth/register",
        json={"email": "ana@gmail.com", "password": "long-secret"},
    )
    assert response.status_code == 201
    # The owner verified the email, so the password is theirs.
    token = re.search(r"#verify_token=(\S+)", sent_emails[0][2]).group(1)
    assert client.post(f"{prefix}/auth/verify", json={"token": token}).status_code == 200

    fake_google_account(monkeypatch, app_module, "ana@gmail.com")
    google_login(client, prefix)
    assert get_me(client, prefix).status_code == 200

    response = client.post(
        f"{prefix}/auth/jwt/login",
        data={"username": "ana@gmail.com", "password": "long-secret"},
    )
    assert response.status_code == 200


def google_callback(client, prefix, **params):
    return client.get(f"{prefix}/auth/google/callback", params=params, follow_redirects=False)


def assert_back_to_login_with_error(client, prefix, response, error):
    assert response.status_code == 307
    assert response.headers["location"] == f"{prefix}/login#error={error}"
    assert "google_oauth_state" not in client.cookies


def test_google_callback_rejects_bad_state(client, prefix, app_module, monkeypatch):
    exchanged_codes = []

    async def verify_and_process(request, **kwargs):
        exchanged_codes.append(request.query_params["code"])

    fake_google_account(monkeypatch, app_module, "new@gmail.com")
    monkeypatch.setattr(app_module.google_sso, "verify_and_process", verify_and_process)

    # No state cookie: a login this browser never started (login CSRF).
    response = google_callback(client, prefix, code="test", state="forged")
    assert_back_to_login_with_error(client, prefix, response, "GOOGLE_FAILED")

    # The browser started a login, but the state in the URL isn't the one sent to Google.
    start_google_login(client, prefix)
    response = google_callback(client, prefix, code="test", state="forged")
    assert_back_to_login_with_error(client, prefix, response, "GOOGLE_FAILED")
    assert exchanged_codes == []


def test_google_callback_when_the_user_cancels(client, prefix, app_module, monkeypatch):
    fake_google_account(monkeypatch, app_module, "new@gmail.com")
    state = start_google_login(client, prefix)

    response = google_callback(client, prefix, error="access_denied", state=state)
    assert_back_to_login_with_error(client, prefix, response, "GOOGLE_CANCELLED")


def test_google_callback_when_google_fails(client, prefix, app_module, monkeypatch):
    # Whatever goes wrong while talking to Google, the user lands on the sign-in
    # page with a readable message instead of an error page.
    fake_google_account(monkeypatch, app_module, "new@gmail.com")
    for failure in (SSOLoginError(401, "User is not verified with Google"), ConnectionError("network down")):
        # failure=failure binds this iteration's error, not whatever the loop ends on.
        async def verify_and_process(request, failure=failure, **kwargs):
            raise failure

        monkeypatch.setattr(app_module.google_sso, "verify_and_process", verify_and_process)
        state = start_google_login(client, prefix)
        response = google_callback(client, prefix, code="test", state=state)
        assert_back_to_login_with_error(client, prefix, response, "GOOGLE_FAILED")


def test_google_state_cookie_is_httponly_and_scoped(client, prefix, app_module, monkeypatch):
    fake_google_account(monkeypatch, app_module, "new@gmail.com")

    response = client.get(f"{prefix}/auth/google/login", follow_redirects=False)
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie
    assert f"path={prefix}/auth/google/callback" in cookie
