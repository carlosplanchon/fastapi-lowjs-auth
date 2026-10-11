import re
from datetime import datetime, timedelta, timezone

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


def test_changing_the_password_ends_every_session(client, prefix):
    register(client, prefix)
    sign_in(client, prefix)

    response = client.patch(f"{prefix}/users/me", json={"password": "new-long-secret"})
    assert response.status_code == 200
    assert client.get(f"{prefix}/me").status_code == 401


def test_sessions_expire(client, prefix, app_module):
    register(client, prefix)
    sign_in(client, prefix)

    too_old = datetime.now(timezone.utc) - timedelta(seconds=SESSION_LIFETIME_SECONDS + 60)
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
