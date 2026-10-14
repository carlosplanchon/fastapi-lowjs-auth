import asyncio
import importlib
import os
import sys
import uuid
from pathlib import Path

import fastapi_users.manager
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from fastapi_users.password import PasswordHelper
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from sqlalchemy import make_url, text
from sqlalchemy.ext.asyncio import create_async_engine

ALEMBIC_INI = Path(__file__).parent.parent / "alembic.ini"
SRC = (Path(__file__).parent.parent / "src").resolve()
# The app's modules that don't read the config. Tests import from them directly,
# so they stay the same objects: the models' classes, for one.
CONFIG_FREE_MODULES = {"models", "sessions", "origin_check", "security_headers"}

# The tests run on SQLite. With a Postgres URL here, like
# postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/postgres, they run on
# Postgres: each test gets a database of its own, created and dropped through
# that connection. CI runs them both ways.
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


def pytest_report_header():
    return f"database: {'Postgres (TEST_DATABASE_URL)' if TEST_DATABASE_URL else 'SQLite'}"


def assert_off_the_event_loop():
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise AssertionError("A password was hashed on the event loop, which stalls every other request")


class CheapPasswordHelper(PasswordHelper):
    """Argon2 at its lowest cost, for speed, failing any test that hashes on the event loop."""

    def __init__(self):
        super().__init__(PasswordHash((Argon2Hasher(time_cost=1, memory_cost=8, parallelism=1),)))

    def hash(self, password):
        assert_off_the_event_loop()
        return super().hash(password)

    def verify_and_update(self, plain_password, hashed_password):
        assert_off_the_event_loop()
        return super().verify_and_update(plain_password, hashed_password)


@pytest.fixture(autouse=True)
def cheap_password_hashes(monkeypatch):
    monkeypatch.setattr(fastapi_users.manager, "PasswordHelper", CheapPasswordHelper)


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
        # in memory), so import its modules fresh each time.
        for name, module in list(sys.modules.items()):
            path = getattr(module, "__file__", None)
            if path and Path(path).resolve().parent == SRC and name not in CONFIG_FREE_MODULES:
                del sys.modules[name]
        return importlib.import_module("shared")

    return load


@pytest.fixture
def alembic_config():
    return Config(str(ALEMBIC_INI))


async def run_on_postgres(statement):
    # Outside a transaction: CREATE DATABASE and DROP DATABASE need that.
    engine = create_async_engine(TEST_DATABASE_URL, isolation_level="AUTOCOMMIT")
    try:
        async with engine.connect() as connection:
            await connection.execute(text(statement))
    finally:
        await engine.dispose()


@pytest.fixture
def database_url(tmp_path):
    """A fresh, empty database for this test: a SQLite file, or a Postgres database."""
    if not TEST_DATABASE_URL:
        yield f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
        return
    name = f"test_{uuid.uuid4().hex}"
    asyncio.run(run_on_postgres(f'CREATE DATABASE "{name}"'))
    yield make_url(TEST_DATABASE_URL).set(database=name)
    # FORCE closes any connection a failed test left open.
    asyncio.run(run_on_postgres(f'DROP DATABASE "{name}" WITH (FORCE)'))


@pytest.fixture
def make_app(database_url, load_shared, alembic_config):
    """Return a function that imports the app on a fresh, migrated database."""

    def make(**config):
        shared = load_shared(**config)
        # Point the app at the test database before it creates its engine, and
        # create the tables with the same migrations as production.
        shared.DB_URL = database_url
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
    return app_module.ROOT_PREFIX


@pytest.fixture
def sent_emails(app_module, monkeypatch):
    """Emails the app sends during the test, as (to, subject, body) tuples."""
    emails = []
    monkeypatch.setattr(app_module.users.mailer, "send_email", lambda *email: emails.append(email))
    return emails
