def register(client, prefix, email="ana@example.com", password="long-secret"):
    response = client.post(f"{prefix}/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201


def sign_in(client, prefix, password="long-secret"):
    return client.post(f"{prefix}/auth/cookie/login", data={"username": "ana@example.com", "password": password})


def bearer_token(client, prefix):
    response = client.post(f"{prefix}/auth/jwt/login", data={"username": "ana@example.com", "password": "long-secret"})
    return response.json()["access_token"]


def change_password(client, prefix, current="long-secret", new="new-long-secret", **kwargs):
    return client.post(
        f"{prefix}/auth/change-password",
        json={"current_password": current, "new_password": new},
        **kwargs,
    )


def test_changing_the_password(client, prefix):
    register(client, prefix)
    assert sign_in(client, prefix).status_code == 204

    assert change_password(client, prefix).status_code == 204
    assert sign_in(client, prefix, "long-secret").status_code == 400
    assert sign_in(client, prefix, "new-long-secret").status_code == 204


def test_a_wrong_current_password_changes_nothing(client, prefix):
    register(client, prefix)
    sign_in(client, prefix)

    response = change_password(client, prefix, current="not-my-password")
    assert response.status_code == 400
    assert response.json()["detail"] == "CHANGE_PASSWORD_BAD_CREDENTIALS"
    assert client.get(f"{prefix}/me").status_code == 200
    assert sign_in(client, prefix, "long-secret").status_code == 204


def test_the_new_password_must_be_valid(client, prefix):
    register(client, prefix)
    sign_in(client, prefix)

    response = change_password(client, prefix, new="1234567")
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "CHANGE_PASSWORD_INVALID_PASSWORD"
    assert "8 characters" in response.json()["detail"]["reason"]
    # Nothing changed, so no session ended either.
    assert client.get(f"{prefix}/me").status_code == 200
    assert sign_in(client, prefix, "long-secret").status_code == 204


def test_it_needs_to_be_signed_in(client, prefix):
    register(client, prefix)
    assert change_password(client, prefix).status_code == 401


def test_cross_site_requests_are_rejected(client, prefix):
    register(client, prefix)
    sign_in(client, prefix)

    response = change_password(client, prefix, headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    assert response.json()["detail"] == "CROSS_ORIGIN_REQUEST"
    assert sign_in(client, prefix, "long-secret").status_code == 204


def test_api_clients_change_it_with_their_bearer_token(client, prefix):
    register(client, prefix)
    sign_in(client, prefix)
    browser_cookie = client.cookies["session"]
    client.cookies.clear()

    token = bearer_token(client, prefix)
    response = change_password(client, prefix, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 204
    # No browser session for an API client...
    assert "set-cookie" not in response.headers
    # ...the browser's one ended with the change, and so did the token itself.
    assert client.get(f"{prefix}/me", headers={"Cookie": f"session={browser_cookie}"}).status_code == 401
    assert client.get(f"{prefix}/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_a_dead_session_cookie_does_not_get_renewed(client, prefix):
    # A browser with an old session cookie that signs in with a Bearer token
    # (e.g. Swagger's "Authorize") isn't signed in with the cookie.
    register(client, prefix)
    sign_in(client, prefix)
    dead_cookie = client.cookies["session"]
    assert client.post(f"{prefix}/auth/cookie/logout").status_code == 204

    response = change_password(client, prefix, headers={
        "Authorization": f"Bearer {bearer_token(client, prefix)}",
        "Cookie": f"session={dead_cookie}",
    })
    assert response.status_code == 204
    assert "set-cookie" not in response.headers


def test_patch_users_me_is_gone(client, prefix):
    # It changed the password without the current one, and the email without
    # confirming it.
    register(client, prefix)
    sign_in(client, prefix)

    response = client.patch(f"{prefix}/users/me", json={"password": "new-long-secret", "email": "eve@example.com"})
    # It falls through to PATCH /users/{id}, which is for superusers only.
    assert response.status_code == 403
    assert client.get(f"{prefix}/me").json()["email"] == "ana@example.com"
    assert sign_in(client, prefix, "long-secret").status_code == 204

    paths = client.get(f"{prefix}/openapi.json").json()["paths"]
    assert set(paths["/users/me"]) == {"get"}
    assert set(paths["/auth/change-password"]) == {"post"}
