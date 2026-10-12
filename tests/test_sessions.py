import re
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from fastapi_users.jwt import generate_jwt
from sqlalchemy import select, update

from models import AccessToken
from sessions import SESSION_LIFETIME_SECONDS, hash_token


def register(client, prefix, email="ana@example.com", password="long-secret"):
    response = client.post(f"{prefix}/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201


def sign_in(client, prefix, password="long-secret", **kwargs):
    return client.post(
        f"{prefix}/auth/cookie/login",
        data={"username": "ana@example.com", "password": password},
        **kwargs,
    )


def bearer_token(client, prefix, password="long-secret"):
    response = client.post(f"{prefix}/auth/jwt/login", data={"username": "ana@example.com", "password": password})
    return response.json()["access_token"]


def me_with_bearer(client, prefix, token):
    # Only the token: no session cookie that could sign the request in instead.
    return client.get(f"{prefix}/me", headers={"Authorization": f"Bearer {token}", "Cookie": ""})


def run_in_app(client, app_module, statement):
    """Run a SQL statement on the app's database, on the app's event loop."""

    async def run():
        async with app_module.async_session_maker() as session:
            result = await session.execute(statement)
            await session.commit()
            return result

    return client.portal.call(run)


def test_sign_in_sets_an_httponly_session_cookie(client, prefix):
    register(client, prefix)
    response = sign_in(client, prefix)
    assert response.status_code == 204

    cookie = response.headers["set-cookie"].lower()
    assert cookie.startswith("session=")
    for attribute in ("httponly", "samesite=lax", "secure", f"path={prefix or '/'}",
                      f"max-age={SESSION_LIFETIME_SECONDS}"):
        assert attribute in cookie
    # The cookie alone is enough: no Authorization header.
    assert client.get(f"{prefix}/me").status_code == 200


def test_the_database_keeps_only_a_hash_of_the_session_token(client, prefix, app_module):
    register(client, prefix)
    sign_in(client, prefix)
    token = client.cookies["session"]

    stored = run_in_app(client, app_module, select(AccessToken.token)).scalars().all()
    assert stored == [hash_token(token)]
    assert token not in stored


def test_signing_out_ends_the_session(client, prefix):
    register(client, prefix)
    sign_in(client, prefix)
    token = client.cookies["session"]

    response = client.post(f"{prefix}/auth/cookie/logout")
    assert response.status_code == 204
    assert "session" not in client.cookies
    # A copy of the old cookie doesn't work anymore either.
    assert client.get(f"{prefix}/me", headers={"Cookie": f"session={token}"}).status_code == 401


def test_resetting_the_password_ends_every_session(client, prefix, sent_emails):
    register(client, prefix)
    sign_in(client, prefix)
    assert client.get(f"{prefix}/me").status_code == 200

    client.post(f"{prefix}/auth/forgot-password", json={"email": "ana@example.com"})
    token = re.search(r"#reset_token=(\S+)", sent_emails[-1][2]).group(1)
    response = client.post(f"{prefix}/auth/reset-password", json={"token": token, "password": "new-long-secret"})
    assert response.status_code == 200

    assert client.get(f"{prefix}/me").status_code == 401


def test_changing_the_password_ends_the_other_sessions_and_renews_this_one(client, prefix, app_module):
    register(client, prefix)
    sign_in(client, prefix)
    other = client.cookies["session"]  # another device
    client.cookies.clear()
    sign_in(client, prefix)
    this = client.cookies["session"]

    response = client.post(
        f"{prefix}/auth/change-password",
        json={"current_password": "long-secret", "new_password": "new-long-secret"},
    )
    assert response.status_code == 204
    cookie = response.headers["set-cookie"].lower()
    for attribute in ("httponly", "samesite=lax", "secure", f"path={prefix or '/'}"):
        assert attribute in cookie

    # This browser carries on with a new session; the old ones are over.
    new = client.cookies["session"]
    assert new not in (this, other)
    assert client.get(f"{prefix}/me").status_code == 200
    for old in (this, other):
        assert client.get(f"{prefix}/me", headers={"Cookie": f"session={old}"}).status_code == 401
    stored = run_in_app(client, app_module, select(AccessToken.token)).scalars().all()
    assert stored == [hash_token(new)]


def test_signing_out_other_devices_ends_them_and_renews_this_session(client, prefix, app_module):
    register(client, prefix)
    sign_in(client, prefix)
    other = client.cookies["session"]  # another device
    client.cookies.clear()
    sign_in(client, prefix)
    this = client.cookies["session"]

    response = client.post(f"{prefix}/auth/cookie/logout-others")
    assert response.status_code == 204
    assert "httponly" in response.headers["set-cookie"].lower()

    new = client.cookies["session"]
    assert new not in (this, other)
    assert client.get(f"{prefix}/me").status_code == 200
    # The other device is out, and so is any copy of this browser's old cookie.
    for old in (this, other):
        assert client.get(f"{prefix}/me", headers={"Cookie": f"session={old}"}).status_code == 401
    stored = run_in_app(client, app_module, select(AccessToken.token)).scalars().all()
    assert stored == [hash_token(new)]
    # The password stays the same.
    client.cookies.clear()
    assert sign_in(client, prefix).status_code == 204


def test_signing_out_other_devices_needs_a_session_from_this_site(client, prefix):
    assert client.post(f"{prefix}/auth/cookie/logout-others").status_code == 401

    register(client, prefix)
    sign_in(client, prefix)
    response = client.post(f"{prefix}/auth/cookie/logout-others", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    assert client.get(f"{prefix}/me").status_code == 200


def test_api_clients_can_sign_out_every_browser(client, prefix):
    register(client, prefix)
    sign_in(client, prefix)
    browser_cookie = client.cookies["session"]
    client.cookies.clear()
    response = client.post(
        f"{prefix}/auth/jwt/login",
        data={"username": "ana@example.com", "password": "long-secret"},
    )
    token = response.json()["access_token"]

    response = client.post(f"{prefix}/auth/cookie/logout-others", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 204
    assert "set-cookie" not in response.headers
    assert client.get(f"{prefix}/me", headers={"Cookie": f"session={browser_cookie}"}).status_code == 401
    # The password didn't change, so the token still works.
    assert me_with_bearer(client, prefix, token).status_code == 200


def test_bearer_tokens_stop_working_when_the_password_changes(client, prefix, sent_emails):
    register(client, prefix)
    before_change = bearer_token(client, prefix)
    sign_in(client, prefix)
    response = client.post(
        f"{prefix}/auth/change-password",
        json={"current_password": "long-secret", "new_password": "new-long-secret"},
    )
    assert response.status_code == 204
    assert me_with_bearer(client, prefix, before_change).status_code == 401

    # A reset ends them too.
    before_reset = bearer_token(client, prefix, "new-long-secret")
    assert me_with_bearer(client, prefix, before_reset).status_code == 200
    client.post(f"{prefix}/auth/forgot-password", json={"email": "ana@example.com"})
    token = re.search(r"#reset_token=(\S+)", sent_emails[-1][2]).group(1)
    client.post(f"{prefix}/auth/reset-password", json={"token": token, "password": "newer-long-secret"})
    assert me_with_bearer(client, prefix, before_reset).status_code == 401
    assert me_with_bearer(client, prefix, bearer_token(client, prefix, "newer-long-secret")).status_code == 200


def test_bearer_tokens_without_the_password_fingerprint_are_refused(client, prefix, app_module):
    # Like the ones issued before tokens carried it: correctly signed, but refused.
    register(client, prefix)
    user_id = me_with_bearer(client, prefix, bearer_token(client, prefix)).json()["id"]
    token = generate_jwt({"sub": user_id, "aud": ["fastapi-users:auth"]}, app_module.JWT_SIGNING_SECRET_KEY, 3600)
    assert me_with_bearer(client, prefix, token).status_code == 401


def test_signing_in_deletes_that_users_expired_sessions(client, prefix, app_module):
    register(client, prefix)
    register(client, prefix, email="bob@example.com")
    sign_in(client, prefix)
    client.cookies.clear()
    client.post(f"{prefix}/auth/cookie/login", data={"username": "bob@example.com", "password": "long-secret"})
    bob = client.cookies["session"]
    client.cookies.clear()
    too_old = datetime.now(UTC) - timedelta(seconds=SESSION_LIFETIME_SECONDS + 60)
    run_in_app(client, app_module, update(AccessToken).values(created_at=too_old))

    sign_in(client, prefix)
    # Ana's expired session is gone; Bob's waits for Bob, or for the next start.
    stored = run_in_app(client, app_module, select(AccessToken.token)).scalars().all()
    assert set(stored) == {hash_token(client.cookies["session"]), hash_token(bob)}


def test_starting_the_app_deletes_every_expired_session(make_app):
    app_module = make_app()
    with TestClient(app_module.app, base_url="https://testserver") as client:
        register(client, "")
        sign_in(client, "")
        expired = client.cookies["session"]
        client.cookies.clear()
        sign_in(client, "")
        current = client.cookies["session"]
        too_old = datetime.now(UTC) - timedelta(seconds=SESSION_LIFETIME_SECONDS + 60)
        run_in_app(
            client, app_module,
            update(AccessToken).where(AccessToken.token == hash_token(expired)).values(created_at=too_old),
        )

    # The next start (a deploy, say) deletes the expired one and keeps the other.
    with TestClient(app_module.app, base_url="https://testserver") as client:
        stored = run_in_app(client, app_module, select(AccessToken.token)).scalars().all()
    assert stored == [hash_token(current)]


def test_sessions_expire(client, prefix, app_module):
    register(client, prefix)
    sign_in(client, prefix)

    too_old = datetime.now(UTC) - timedelta(seconds=SESSION_LIFETIME_SECONDS + 60)
    run_in_app(client, app_module, update(AccessToken).values(created_at=too_old))
    assert client.get(f"{prefix}/me").status_code == 401


def test_cross_site_requests_are_rejected(client, prefix):
    register(client, prefix)

    response = sign_in(client, prefix, headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    assert response.json()["detail"] == "CROSS_ORIGIN_REQUEST"

    # The site itself: the host the browser is talking to, or the public URL.
    assert sign_in(client, prefix, headers={"Origin": "https://testserver"}).status_code == 204
    assert sign_in(client, prefix, headers={"Origin": "https://auth.example"}).status_code == 204
    # Reading is never blocked.
    assert client.get(f"{prefix}/me", headers={"Origin": "https://evil.example"}).status_code == 200


def test_bearer_tokens_still_work_for_api_clients(client, prefix):
    register(client, prefix)
    response = client.post(
        f"{prefix}/auth/jwt/login",
        data={"username": "ana@example.com", "password": "long-secret"},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert client.get(f"{prefix}/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
