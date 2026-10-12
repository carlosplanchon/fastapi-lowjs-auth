import importlib
import sys
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient


ALEMBIC_INI = Path(__file__).parent.parent / "alembic.ini"


CONFIG = """
[app]
ROOT_PATH = "{root_path}"
PUBLIC_URL = "{public_url}"

[database]
DB_HOST = "db.example"
DB_PORT = 5432
DB_NAME = "unused"
DB_USERNAME = "unused"
DB_PASSWORD = "{db_password}"

[security]
JWT_SIGNING_SECRET_KEY = "test-secret-at-least-32-bytes-long"

[google]
GOOGLE_CLIENT_ID = "test-client-id"
GOOGLE_CLIENT_SECRET = "test-client-secret"
GOOGLE_REDIRECT_URI = "http://testserver{prefix}/auth/google/callback"

[email]
BACKEND = "console"
FROM_ADDRESS = "no-reply@auth.example"
"""


@pytest.fixture
def load_shared(tmp_path, monkeypatch):
    """Return a function that writes a config.toml and imports shared fresh from it."""

    def load(root_path="", db_password="unused", public_url="https://auth.example", extra_config=""):
        # Like a real deployment, Google redirects back to the prefixed callback URL.
        prefix = f"/{root_path}" if root_path else ""
        config = tmp_path / "config.toml"
        config.write_text(
            CONFIG.format(root_path=root_path, prefix=prefix, db_password=db_password, public_url=public_url)
            + extra_config
        )
        monkeypatch.setenv("CONFIG_PATH", str(config))

        # The app reads its config at import time (and keeps rate limit counters
        # in memory), so import it fresh each time.
        for name in ("shared", "mailer", "rate_limits", "auth_backend_api"):
            sys.modules.pop(name, None)
        return importlib.import_module("shared")

    return load


@pytest.fixture
def alembic_config():
    return Config(str(ALEMBIC_INI))


@pytest.fixture
def make_app(tmp_path, load_shared, alembic_config):
    """Return a function that imports the app on a fresh, migrated SQLite database."""

    def make(**config):
        shared = load_shared(**config)
        # Point the DB at a throwaway SQLite file before the app creates its engine,
        # and create the tables with the same migrations as production.
        shared.DB_URL = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
        command.upgrade(alembic_config, "head")
        return importlib.import_module("auth_backend_api")

    return make


@pytest.fixture(params=["", "myapp"], ids=["no-root-path", "root-path"])
def app_module(request, make_app):
    return make_app(root_path=request.param)


@pytest.fixture
def client(app_module):
    # https, like production: with an https PUBLIC_URL the session cookie is
    # Secure, and the client only sends it back over https.
    with TestClient(app_module.app, base_url="https://testserver") as client:
        yield client


@pytest.fixture
def prefix(app_module):
    return app_module.root_prefix


@pytest.fixture
def sent_emails(app_module, monkeypatch):
    """Emails the app sends during the test, as (to, subject, body) tuples."""
    emails = []
    monkeypatch.setattr(app_module.mailer, "send_email", lambda *email: emails.append(email))
    return emails
