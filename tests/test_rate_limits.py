from fastapi.testclient import TestClient


def register(client, prefix, email="ana@example.com", password="long-secret"):
    return client.post(f"{prefix}/auth/register", json={"email": email, "password": password})


def sign_in(client, prefix, email="ana@example.com", password="long-secret"):
    return client.post(f"{prefix}/auth/jwt/login", data={"username": email, "password": password})


def ask_for_email(client, prefix, path="forgot-password", email="ana@example.com"):
    return client.post(f"{prefix}/auth/{path}", json={"email": email})


def assert_too_many(response):
    assert response.status_code == 429
    assert response.json()["detail"] == "TOO_MANY_REQUESTS"
    assert int(response.headers["Retry-After"]) > 0


def app_with_limits(make_app, **limits):
    settings = "".join(f'{name} = "{value}"\n' for name, value in limits.items())
    return make_app(extra_config=f"\n[rate_limits]\n{settings}").app


def test_login_blocks_after_five_failures_in_a_row(client, prefix):
    assert register(client, prefix).status_code == 201
    for _ in range(5):
        assert sign_in(client, prefix, password="wrong-password").status_code == 400
    # Blocked even with the right password, so guessing gets nowhere.
    assert_too_many(sign_in(client, prefix))


def test_cookie_and_bearer_sign_in_share_the_limit(client, prefix):
    # Alternating between the two sign-in routes doesn't buy extra attempts.
    assert register(client, prefix).status_code == 201
    for backend in ("cookie", "jwt", "cookie", "jwt", "cookie"):
        response = client.post(
            f"{prefix}/auth/{backend}/login",
            data={"username": "ana@example.com", "password": "wrong-password"},
        )
        assert response.status_code == 400
    assert_too_many(sign_in(client, prefix))


def test_changing_the_email_case_does_not_get_around_the_limit(client, prefix):
    # Sign-in ignores the email's case, so the limit must too.
    assert register(client, prefix).status_code == 201
    for email in ("ANA@example.com", "Ana@Example.com", " ana@example.com", "aNa@example.COM", "ana@EXAMPLE.com"):
        assert sign_in(client, prefix, email=email, password="wrong-password").status_code == 400
    assert_too_many(sign_in(client, prefix))


def test_a_successful_login_resets_the_failure_count(client, prefix):
    assert register(client, prefix).status_code == 201
    for _ in range(4):
        assert sign_in(client, prefix, password="wrong-password").status_code == 400
    assert sign_in(client, prefix).status_code == 200
    for _ in range(4):
        assert sign_in(client, prefix, password="wrong-password").status_code == 400
    assert sign_in(client, prefix).status_code == 200


def test_login_attempts_are_limited_per_ip_across_accounts(make_app):
    # One client trying a password on many accounts (password spraying).
    with TestClient(app_with_limits(make_app, LOGIN_ATTEMPTS_PER_IP="3/15minutes")) as client:
        for n in range(3):
            assert sign_in(client, "", email=f"user{n}@example.com").status_code == 400
        assert_too_many(sign_in(client, "", email="one-more@example.com"))


def test_reset_and_verification_emails_share_a_limit_per_address(client, prefix, sent_emails):
    assert register(client, prefix).status_code == 201
    sent_emails.clear()
    for path in ("forgot-password", "request-verify-token", "forgot-password"):
        assert ask_for_email(client, prefix, path).status_code == 202
    assert_too_many(ask_for_email(client, prefix, "request-verify-token"))
    assert len(sent_emails) == 3
    # Other addresses keep their own budget.
    assert ask_for_email(client, prefix, email="bob@example.com").status_code == 202


def test_the_email_limit_does_not_reveal_which_addresses_exist(client, prefix):
    # An address without an account reaches the limit exactly like a real one.
    for _ in range(3):
        assert ask_for_email(client, prefix, email="nobody@example.com").status_code == 202
    assert_too_many(ask_for_email(client, prefix, email="nobody@example.com"))


def test_email_requests_are_limited_per_ip(client, prefix):
    for n in range(10):
        assert ask_for_email(client, prefix, email=f"user{n}@example.com").status_code == 202
    assert_too_many(ask_for_email(client, prefix, email="user10@example.com"))


def test_other_auth_routes_are_not_limited(client, prefix):
    for _ in range(40):
        assert client.post(f"{prefix}/auth/verify", json={"token": "invalid"}).status_code == 400


def test_registrations_are_limited_per_ip(make_app):
    with TestClient(app_with_limits(make_app, REGISTRATIONS_PER_IP="2/hour")) as client:
        assert register(client, "", email="a@example.com").status_code == 201
        assert register(client, "", email="b@example.com").status_code == 201
        assert_too_many(register(client, "", email="c@example.com"))
