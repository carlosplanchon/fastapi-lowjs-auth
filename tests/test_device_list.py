from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from models import AccessToken
from sessions import (
    SESSION_COOKIE_NAME,
    SESSION_LIFETIME_SECONDS,
    describe_device,
    hash_token,
)

FIREFOX_ON_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
SAFARI_ON_IPHONE = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1"
)
CHROME_ON_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36"
)
EDGE_ON_WINDOWS = CHROME_ON_WINDOWS + " Edg/130.0.0.0"
SAFARI_ON_MACOS = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.0 Safari/605.1.15"
)
CHROME_ON_ANDROID = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Mobile Safari/537.36"
)


def register(client, prefix, email="ana@example.com", password="long-secret"):
    response = client.post(f"{prefix}/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201


def sign_in(client, prefix, user_agent=FIREFOX_ON_LINUX, email="ana@example.com"):
    response = client.post(
        f"{prefix}/auth/cookie/login",
        data={"username": email, "password": "long-secret"},
        headers={"User-Agent": user_agent},
    )
    assert response.status_code == 204
    return client.cookies[SESSION_COOKIE_NAME]


def sign_in_on_two_devices(client, prefix):
    """Ana signs in on her phone, then on this browser. Returns the phone's cookie."""
    register(client, prefix)
    phone = sign_in(client, prefix, SAFARI_ON_IPHONE)
    client.cookies.clear()
    sign_in(client, prefix)
    return phone


def list_sessions(client, prefix, **kwargs):
    response = client.get(f"{prefix}/auth/sessions", **kwargs)
    assert response.status_code == 200
    return response.json()


def me_with_cookie(client, prefix, cookie):
    return client.get(f"{prefix}/me", headers={"Cookie": f"{SESSION_COOKIE_NAME}={cookie}"})


def run_in_app(client, app_module, statement):
    """Run a SQL statement on the app's database, on the app's event loop."""

    async def run():
        async with app_module.database.async_session_maker() as session:
            result = await session.execute(statement)
            await session.commit()
            return result

    return client.portal.call(run)


def test_the_list_shows_each_signed_in_device(client, prefix):
    sign_in_on_two_devices(client, prefix)

    sessions = list_sessions(client, prefix)
    # This browser first.
    assert [(session["device"], session["current"]) for session in sessions] == [
        ("Firefox on Linux", True),
        ("Safari on iPhone", False),
    ]
    assert [session["user_agent"] for session in sessions] == [FIREFOX_ON_LINUX, SAFARI_ON_IPHONE]
    # The address TestClient sends from.
    assert {session["ip_address"] for session in sessions} == {"testclient"}


def test_the_list_shows_the_ip_address_each_device_signed_in_from(make_app):
    app_module = make_app()
    with TestClient(app_module.app, base_url="https://testserver", client=("203.0.113.7", 50000)) as client:
        register(client, "")
        sign_in(client, "")
        [session] = list_sessions(client, "")
    assert session["ip_address"] == "203.0.113.7"


def test_the_list_shows_nothing_that_signs_in(client, prefix, app_module):
    phone = sign_in_on_two_devices(client, prefix)
    this = client.cookies[SESSION_COOKIE_NAME]

    response = client.get(f"{prefix}/auth/sessions")
    stored = run_in_app(client, app_module, select(AccessToken.token)).scalars().all()
    # Neither the cookies' tokens nor the rows' keys, their hashes.
    for secret in [phone, this, *stored]:
        assert secret not in response.text


def test_signing_out_another_device(client, prefix):
    phone = sign_in_on_two_devices(client, prefix)
    on_phone = list_sessions(client, prefix)[1]

    response = client.delete(f"{prefix}/auth/sessions/{on_phone['id']}")
    assert response.status_code == 204
    assert "set-cookie" not in response.headers
    assert me_with_cookie(client, prefix, phone).status_code == 401
    assert client.get(f"{prefix}/me").status_code == 200
    assert [session["device"] for session in list_sessions(client, prefix)] == ["Firefox on Linux"]

    # Already over: nothing left to end.
    response = client.delete(f"{prefix}/auth/sessions/{on_phone['id']}")
    assert response.status_code == 404
    assert response.json()["detail"] == "SESSION_NOT_FOUND"


def test_signing_out_this_device_from_the_list(client, prefix):
    register(client, prefix)
    this = sign_in(client, prefix)
    [session] = list_sessions(client, prefix)

    response = client.delete(f"{prefix}/auth/sessions/{session['id']}")
    assert response.status_code == 204
    # As with signing out: the cookie goes too.
    assert SESSION_COOKIE_NAME not in client.cookies
    assert me_with_cookie(client, prefix, this).status_code == 401


def test_nobody_sees_or_ends_the_sessions_of_another_account(client, prefix):
    register(client, prefix)
    ana = sign_in(client, prefix)
    [anas_session] = list_sessions(client, prefix)
    client.cookies.clear()
    register(client, prefix, email="bob@example.com")
    sign_in(client, prefix, email="bob@example.com")

    assert [session["current"] for session in list_sessions(client, prefix)] == [True]
    response = client.delete(f"{prefix}/auth/sessions/{anas_session['id']}")
    assert response.status_code == 404
    assert me_with_cookie(client, prefix, ana).status_code == 200


def test_the_list_needs_a_session_and_ending_one_needs_this_site(client, prefix):
    assert client.get(f"{prefix}/auth/sessions").status_code == 401
    assert client.delete(f"{prefix}/auth/sessions/anything").status_code == 401

    phone = sign_in_on_two_devices(client, prefix)
    on_phone = list_sessions(client, prefix)[1]
    response = client.delete(f"{prefix}/auth/sessions/{on_phone['id']}", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    assert me_with_cookie(client, prefix, phone).status_code == 200


def test_api_clients_can_list_and_end_browser_sessions(client, prefix):
    phone = sign_in_on_two_devices(client, prefix)
    client.cookies.clear()
    response = client.post(f"{prefix}/auth/jwt/login", data={"username": "ana@example.com", "password": "long-secret"})
    bearer = {"Authorization": f"Bearer {response.json()['access_token']}"}

    sessions = list_sessions(client, prefix, headers=bearer)
    # Signed in with a Bearer JWT: none of them is this one.
    assert [session["current"] for session in sessions] == [False, False]
    on_phone = next(session for session in sessions if session["device"] == "Safari on iPhone")
    assert client.delete(f"{prefix}/auth/sessions/{on_phone['id']}", headers=bearer).status_code == 204
    assert me_with_cookie(client, prefix, phone).status_code == 401


def test_expired_sessions_arent_listed(client, prefix, app_module):
    phone = sign_in_on_two_devices(client, prefix)
    too_old = datetime.now(UTC) - timedelta(seconds=SESSION_LIFETIME_SECONDS + 60)
    run_in_app(
        client, app_module,
        update(AccessToken).where(AccessToken.token == hash_token(phone)).values(created_at=too_old),
    )

    assert [session["device"] for session in list_sessions(client, prefix)] == ["Firefox on Linux"]


def test_each_session_saves_when_it_was_last_used(client, prefix, app_module):
    register(client, prefix)
    sign_in(client, prefix)

    def last_used():
        return run_in_app(client, app_module, select(AccessToken.last_used_at)).scalar_one()

    def set_last_used(when):
        run_in_app(client, app_module, update(AccessToken).values(last_used_at=when))

    # Used after a day: saved.
    set_last_used(datetime.now(UTC) - timedelta(days=1))
    before = datetime.now(UTC)
    assert client.get(f"{prefix}/me").status_code == 200
    assert last_used() >= before
    # Used again a minute later: not written again.
    a_minute_ago = datetime.now(UTC) - timedelta(minutes=1)
    set_last_used(a_minute_ago)
    assert client.get(f"{prefix}/me").status_code == 200
    assert last_used() == a_minute_ago


def test_sessions_from_before_the_list_show_up_too(client, prefix, app_module):
    phone = sign_in_on_two_devices(client, prefix)
    # Signed in before sessions kept a browser, an address and a last use.
    run_in_app(
        client, app_module,
        update(AccessToken)
        .where(AccessToken.token == hash_token(phone))
        .values(user_agent=None, ip_address=None, last_used_at=None),
    )

    on_phone = list_sessions(client, prefix)[1]
    assert (on_phone["device"], on_phone["user_agent"], on_phone["ip_address"]) == ("Unknown device", None, None)
    assert on_phone["last_used_at"] == on_phone["signed_in_at"]


def test_long_user_agents_are_cut_to_fit(client, prefix, app_module):
    # Postgres would refuse it whole, and the sign-in with it.
    user_agent = "Mozilla/5.0 " + "x" * 1000
    register(client, prefix)
    sign_in(client, prefix, user_agent)

    assert run_in_app(client, app_module, select(AccessToken.user_agent)).scalar_one() == user_agent[:255]


@pytest.mark.parametrize(
    ("user_agent", "device"),
    [
        (FIREFOX_ON_LINUX, "Firefox on Linux"),
        (SAFARI_ON_IPHONE, "Safari on iPhone"),
        (CHROME_ON_WINDOWS, "Chrome on Windows"),
        (EDGE_ON_WINDOWS, "Edge on Windows"),
        (SAFARI_ON_MACOS, "Safari on macOS"),
        (CHROME_ON_ANDROID, "Chrome on Android"),
        ("curl/8.5.0", "curl"),
        ("python-httpx/0.28.1", "python-httpx"),
        # The header is free text: one word of it, so no sentence ends up in the emails.
        ("Ignore this email, it was a test/1.0", "Ignore"),
        ("<b>Bot</b>", "Unknown device"),
        ("", "Unknown device"),
        (None, "Unknown device"),
    ],
)
def test_devices_are_named_by_browser_and_system(user_agent, device):
    assert describe_device(user_agent) == device
