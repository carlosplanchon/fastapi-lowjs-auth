import re

from fastapi.testclient import TestClient


def csp_directives(response):
    policy = response.headers["content-security-policy"]
    return dict(directive.strip().split(" ", 1) for directive in policy.split(";"))


def test_the_login_page_gets_a_strict_content_security_policy(client, prefix):
    directives = csp_directives(client.get(f"{prefix}/login"))

    assert directives["default-src"] == "'none'"
    # Only the app's own scripts: no inline code and no eval (Alpine's CSP build).
    assert directives["script-src"] == "'self'"
    for name in ("style-src", "img-src", "connect-src", "form-action"):
        assert directives[name] == "'self'"
    assert directives["frame-ancestors"] == "'none'"
    assert directives["base-uri"] == "'none'"


def test_the_login_page_has_no_inline_code(client, prefix):
    # The CSP blocks inline scripts, styles and event handlers without a word:
    # everything must load from a file.
    html = client.get(f"{prefix}/login").text
    scripts = re.findall(r"<script\b[^>]*>", html)
    assert scripts
    assert all(" src=" in tag for tag in scripts)
    assert "<style" not in html
    for tag in re.findall(r"<[a-z][^>]*>", html):
        assert not re.search(r"\s(?:style|on[a-z]+)=", tag), tag


def test_every_response_gets_the_basic_security_headers(client, prefix):
    responses = [
        client.get(f"{prefix}/login"),
        client.get(f"{prefix}/static/app.js"),
        client.get(f"{prefix}/me"),
        # Rejected by the Origin check, before it reaches the app.
        client.post(f"{prefix}/auth/cookie/login", headers={"Origin": "https://evil.example"}),
    ]
    assert [response.status_code for response in responses] == [200, 200, 401, 403]
    for response in responses:
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "same-origin"
        # The tests' PUBLIC_URL is https.
        assert response.headers["strict-transport-security"] == "max-age=31536000"


def test_hsts_only_when_the_public_url_is_https(make_app):
    app = make_app(public_url="http://auth.example").app
    with TestClient(app) as client:
        response = client.get("/login")
    assert response.status_code == 200
    assert "strict-transport-security" not in response.headers


def test_the_api_docs_keep_working(client, prefix):
    # Swagger UI loads from a CDN with inline scripts: the CSP is left out there.
    response = client.get(f"{prefix}/docs")
    assert response.status_code == 200
    assert "content-security-policy" not in response.headers
    assert response.headers["x-frame-options"] == "DENY"
