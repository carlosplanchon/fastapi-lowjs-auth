import pytest
from fastapi_users.db import SQLAlchemyUserDatabase
from sqlalchemy import select, update

from models import AccessToken, User


def register(client, prefix, email="ana@example.com", password="long-secret"):
    response = client.post(f"{prefix}/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201


def sign_in(client, prefix, password="long-secret"):
    return client.post(f"{prefix}/auth/cookie/login", data={"username": "ana@example.com", "password": password})


def bearer_token(client, prefix, email="ana@example.com", password="long-secret"):
    response = client.post(f"{prefix}/auth/jwt/login", data={"username": email, "password": password})
    return response.json()["access_token"]


def delete_account(client, prefix, password="long-secret", **kwargs):
    return client.post(f"{prefix}/auth/delete-account", json={"password": password}, **kwargs)


def run_in_app(client, app_module, statement):
    """Run a SQL statement on the app's database, on the app's event loop."""

    async def run():
        async with app_module.async_session_maker() as session:
            result = await session.execute(statement)
            await session.commit()
            return result

    return client.portal.call(run)


def session_tokens(client, app_module):
    return run_in_app(client, app_module, select(AccessToken.token)).scalars().all()


def test_deleting_the_account(client, prefix, app_module, sent_emails):
    register(client, prefix)
    run_in_app(client, app_module, update(User).values(is_verified=True))
    token = bearer_token(client, prefix)
    sign_in(client, prefix)
    cookie = client.cookies["session"]
    sent_emails.clear()

    response = delete_account(client, prefix)
    assert response.status_code == 204
    set_cookie = response.headers["set-cookie"].lower()
    assert set_cookie.startswith("session=")
    assert "max-age=0" in set_cookie
    assert f"path={prefix or '/'}" in set_cookie
    assert "session" not in client.cookies

    # Nothing left: no sessions, no user...
    assert session_tokens(client, app_module) == []
    assert run_in_app(client, app_module, select(User.email)).scalars().all() == []
    # ...so the old cookie, an earlier Bearer token and the password stop working.
    assert client.get(f"{prefix}/me", headers={"Cookie": f"session={cookie}"}).status_code == 401
    assert client.get(f"{prefix}/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert sign_in(client, prefix).status_code == 400

    [(to, subject, body)] = sent_emails
    assert (to, subject) == ("ana@example.com", "Your account was deleted")
    assert f"https://auth.example{prefix}/login\n" in body

    # The address is free again.
    register(client, prefix)


def test_a_wrong_password_deletes_nothing(client, prefix, sent_emails):
    register(client, prefix)
    sign_in(client, prefix)
    sent_emails.clear()

    response = delete_account(client, prefix, password="not-my-password")
    assert response.status_code == 400
    assert response.json()["detail"] == "DELETE_ACCOUNT_BAD_CREDENTIALS"
    assert "set-cookie" not in response.headers
    assert client.get(f"{prefix}/me").status_code == 200
    assert sent_emails == []


def test_unverified_accounts_get_no_goodbye_email(client, prefix, sent_emails):
    # Anyone can sign up any address: no email unless its owner verified it.
    register(client, prefix)
    sign_in(client, prefix)
    sent_emails.clear()

    assert delete_account(client, prefix).status_code == 204
    assert sent_emails == []


def test_it_needs_a_session_from_this_site(client, prefix):
    register(client, prefix)
    assert delete_account(client, prefix).status_code == 401

    sign_in(client, prefix)
    response = delete_account(client, prefix, headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    assert client.get(f"{prefix}/me").status_code == 200


def test_api_clients_can_delete_with_their_bearer_token(client, prefix):
    register(client, prefix)
    token = bearer_token(client, prefix)

    response = delete_account(client, prefix, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 204
    assert client.get(f"{prefix}/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert sign_in(client, prefix).status_code == 400


def test_a_superuser_deleting_an_account_cleans_up_too(client, prefix, app_module, sent_emails):
    register(client, prefix)
    register(client, prefix, email="admin@example.com")
    run_in_app(client, app_module, update(User).values(is_verified=True))
    run_in_app(client, app_module, update(User).where(User.email == "admin@example.com").values(is_superuser=True))
    sign_in(client, prefix)
    ana_id = client.get(f"{prefix}/me").json()["id"]
    client.cookies.clear()
    admin_token = bearer_token(client, prefix, email="admin@example.com")
    sent_emails.clear()

    response = client.delete(f"{prefix}/users/{ana_id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 204
    assert session_tokens(client, app_module) == []
    assert [(to, subject) for to, subject, _ in sent_emails] == [("ana@example.com", "Your account was deleted")]


def test_a_failed_delete_changes_nothing(client, prefix, app_module, monkeypatch):
    register(client, prefix)
    sign_in(client, prefix)

    async def fail(self, user):
        raise RuntimeError("database down")

    monkeypatch.setattr(SQLAlchemyUserDatabase, "delete", fail)
    with pytest.raises(RuntimeError):
        delete_account(client, prefix)
    # The sessions go in the same transaction as the user: none were deleted.
    assert len(session_tokens(client, app_module)) == 1
    assert client.get(f"{prefix}/me").status_code == 200
