import re
from urllib.parse import parse_qs, urlsplit

from fastapi_sso.sso.base import OpenID
from fastapi_sso.sso.google import GoogleSSO
from starlette.requests import Request

import sessions
from sessions import (
    KNOWN_BROWSER_COOKIE_NAME,
    KNOWN_BROWSER_LIFETIME_SECONDS,
    known_browser_mark,
)

FIREFOX_ON_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
SAFARI_ON_IPHONE = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1"
)


def register(client, prefix, sent_emails, email="ana@example.com", verify=True):
    """Sign up, and verify the address with the emailed link unless verify=False."""
    response = client.post(f"{prefix}/auth/register", json={"email": email, "password": "long-secret"})
    assert response.status_code == 201
    if verify:
        verify_email(client, prefix, sent_emails, email)


def verify_email(client, prefix, sent_emails, email="ana@example.com"):
    body = next(body for to, subject, body in sent_emails if (to, subject) == (email, "Verify your email"))
    token = re.search(r"#verify_token=(\S+)", body).group(1)
    assert client.post(f"{prefix}/auth/verify", json={"token": token}).status_code == 200


def sign_in(client, prefix, user_agent=FIREFOX_ON_LINUX, email="ana@example.com", headers=None):
    response = client.post(
        f"{prefix}/auth/cookie/login",
        data={"username": email, "password": "long-secret"},
        headers={"User-Agent": user_agent, **(headers or {})},
    )
    assert response.status_code == 204
    return response


def sign_in_from_api(client, prefix, user_agent):
    response = client.post(
        f"{prefix}/auth/jwt/login",
        data={"username": "ana@example.com", "password": "long-secret"},
        headers={"User-Agent": user_agent},
    )
    assert response.status_code == 200


def notices(sent_emails, email="ana@example.com"):
    """The bodies of the new sign-in notices sent to that address."""
    return [body for to, subject, body in sent_emails if (to, subject) == (email, "New sign-in to your account")]


def fake_google_account(monkeypatch, email):
    async def get_discovery_document(self):
        return {
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        }

    async def process_login(self, code, request, **kwargs):
        return OpenID(email=email, provider="google", id="google-account-id")

    monkeypatch.setattr(GoogleSSO, "get_discovery_document", get_discovery_document)
    monkeypatch.setattr(GoogleSSO, "process_login", process_login)


def sign_in_with_google(client, prefix, user_agent=FIREFOX_ON_LINUX):
    response = client.get(f"{prefix}/auth/google/login", follow_redirects=False)
    state = parse_qs(urlsplit(response.headers["location"]).query)["state"][0]
    response = client.get(
        f"{prefix}/auth/google/callback",
        params={"code": "test", "state": state},
        headers={"User-Agent": user_agent},
        follow_redirects=False,
    )
    assert response.headers["location"] == f"{prefix}/login"


def test_signing_in_from_a_new_device_emails_the_owner(client, prefix, sent_emails):
    register(client, prefix, sent_emails)
    # A forged Host must not end up in the link.
    sign_in(client, prefix, SAFARI_ON_IPHONE, headers={"host": "evil.example"})

    [body] = notices(sent_emails)
    assert body.startswith(
        "Someone just signed in to your account from a device we don't recognize:\n\n"
        "Safari on iPhone\nIP address testclient\n"
    )
    assert re.search(r"\n\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\n", body)
    assert '"Forgot your password?"' in body
    assert body.endswith(f"\n\nhttps://auth.example{prefix}/login\n")
    assert "evil.example" not in body


def test_a_browser_that_signed_in_before_gets_no_notice(client, prefix, sent_emails):
    register(client, prefix, sent_emails)
    sign_in(client, prefix)
    # Not even after signing out.
    assert client.post(f"{prefix}/auth/cookie/logout").status_code == 204
    sign_in(client, prefix)
    assert len(notices(sent_emails)) == 1

    # The same browser without its cookies, as in a private window, is new.
    client.cookies.clear()
    sign_in(client, prefix)
    assert len(notices(sent_emails)) == 2


def test_before_verifying_sign_ins_just_mark_the_browser(client, prefix, sent_emails):
    # Anyone can sign up someone else's address: it gets no notices until verified.
    register(client, prefix, sent_emails, verify=False)
    sign_in(client, prefix, SAFARI_ON_IPHONE)
    client.cookies.clear()
    # The sign-up page signs in right away, before the address is verified.
    sign_in(client, prefix)
    assert notices(sent_emails) == []

    verify_email(client, prefix, sent_emails)
    sign_in(client, prefix)
    assert notices(sent_emails) == []
    client.cookies.clear()
    sign_in(client, prefix)
    assert len(notices(sent_emails)) == 1


def test_a_browser_remembers_each_account_that_signed_in(client, prefix, sent_emails):
    register(client, prefix, sent_emails)
    register(client, prefix, sent_emails, email="bob@example.com")
    for email in ("ana@example.com", "bob@example.com", "ana@example.com", "bob@example.com"):
        sign_in(client, prefix, email=email)

    assert len(notices(sent_emails)) == 1
    assert len(notices(sent_emails, "bob@example.com")) == 1


def test_past_the_maximum_a_browser_forgets_the_least_recent_account(client, prefix, sent_emails, monkeypatch):
    monkeypatch.setattr(sessions, "KNOWN_BROWSER_MAX_ACCOUNTS", 2)
    accounts = ["ana@example.com", "bob@example.com", "cy@example.com"]
    for email in accounts:
        register(client, prefix, sent_emails, email=email)
        sign_in(client, prefix, email=email)

    # Ana's was forgotten, then Bob's.
    sign_in(client, prefix, email="cy@example.com")
    sign_in(client, prefix, email="ana@example.com")
    assert [len(notices(sent_emails, email)) for email in accounts] == [2, 1, 1]


def test_the_cookie_holds_nothing_but_a_mark_per_account(client, prefix, sent_emails):
    register(client, prefix, sent_emails)
    response = sign_in(client, prefix)

    [cookie] = [c for c in response.headers.get_list("set-cookie") if c.startswith(f"{KNOWN_BROWSER_COOKIE_NAME}=")]
    for attribute in ("httponly", "samesite=lax", "secure", f"path={prefix or '/'}",
                      f"max-age={KNOWN_BROWSER_LIFETIME_SECONDS}"):
        assert attribute in cookie.lower()
    # Neither the email nor the user's id: 16 bytes of a keyed hash.
    assert re.fullmatch(r"[A-Za-z0-9_-]{22}", client.cookies[KNOWN_BROWSER_COOKIE_NAME])


def test_only_the_app_can_make_marks(client, prefix, sent_emails):
    register(client, prefix, sent_emails)
    sign_in(client, prefix)
    user_id = client.get(f"{prefix}/me").json()["id"]

    forged = known_browser_mark("another-secret-at-least-32-bytes-long", user_id)
    for cookie in (forged, "made-up", "x" * 3000):
        sign_in(client, prefix, headers={"Cookie": f"{KNOWN_BROWSER_COOKIE_NAME}={cookie}"})
        # The new cookie keeps only what looks like a mark.
        assert len(client.cookies[KNOWN_BROWSER_COOKIE_NAME]) == (22 + 1 + 22 if cookie == forged else 22)
    assert len(notices(sent_emails)) == 4


def test_api_clients_without_cookies_get_one_notice_each(client, prefix, sent_emails):
    register(client, prefix, sent_emails)
    for user_agent in ("python-httpx/0.28.1", "python-httpx/0.28.1", "curl/8.5.0", "python-httpx/0.28.1"):
        # A script that keeps no cookies, signing in every hour.
        client.cookies.clear()
        sign_in_from_api(client, prefix, user_agent)

    assert [body.split("\n")[2] for body in notices(sent_emails)] == ["python-httpx", "curl"]


def test_api_clients_that_keep_cookies_are_known_like_browsers(client, prefix, sent_emails):
    register(client, prefix, sent_emails)
    sign_in_from_api(client, prefix, "python-httpx/0.28.1")
    # Another program, with the cookie the first answer set.
    sign_in_from_api(client, prefix, "curl/8.5.0")
    sign_in(client, prefix)
    assert len(notices(sent_emails)) == 1


def test_api_clients_are_told_apart_by_ip_address_and_user_agent(client, app_module):
    def notice_due(ip, user_agent, user_id="ana"):
        request = Request({"type": "http", "client": (ip, 50000), "headers": [(b"user-agent", user_agent.encode())]})
        return client.portal.call(app_module.rate_limits.api_client_notice_due, request, user_id)

    assert notice_due("192.0.2.1", "curl/8.5.0")
    assert not notice_due("192.0.2.1", "curl/8.5.0")
    assert notice_due("192.0.2.2", "curl/8.5.0")
    assert notice_due("192.0.2.1", "curl/8.6.0")
    assert notice_due("192.0.2.1", "curl/8.5.0", user_id="bob")


def test_signing_in_with_google_from_a_new_device(client, prefix, sent_emails, monkeypatch):
    fake_google_account(monkeypatch, "ana@gmail.com")
    # Creating the account: whoever signs in owns the address, there's nobody else to tell.
    sign_in_with_google(client, prefix)
    sign_in_with_google(client, prefix)
    assert notices(sent_emails, "ana@gmail.com") == []

    client.cookies.clear()
    sign_in_with_google(client, prefix, SAFARI_ON_IPHONE)
    [body] = notices(sent_emails, "ana@gmail.com")
    assert body.startswith(
        "Someone just signed in to your account with Google from a device we don't recognize:\n\n"
        "Safari on iPhone\n"
    )
    # Its password isn't how they got in.
    assert "your Google account: secure it right away" in body
    assert "Forgot your password?" not in body


def test_no_notice_when_google_takes_over_an_unverified_account(client, prefix, sent_emails, monkeypatch):
    register(client, prefix, sent_emails, email="ana@gmail.com", verify=False)
    fake_google_account(monkeypatch, "ana@gmail.com")
    sign_in_with_google(client, prefix)
    assert notices(sent_emails, "ana@gmail.com") == []
