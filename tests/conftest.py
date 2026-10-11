import importlib
import sys

import pytest
from fastapi.testclient import TestClient


CONFIG = """
[app]
ROOT_PATH = "{root_path}"

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
"""


@pytest.fixture
def load_shared(tmp_path, monkeypatch):
    """Return a function that writes a config.toml and imports shared fresh from it."""

    def load(root_path="", db_password="unused"):
        # Like a real deployment, Google redirects back to the prefixed callback URL.
        prefix = f"/{root_path}" if root_path else ""
        config = tmp_path / "config.toml"
        config.write_text(CONFIG.format(root_path=root_path, prefix=prefix, db_password=db_password))
        monkeypatch.setenv("CONFIG_PATH", str(config))

        # The app reads its config at import time, so import it fresh each time.
        for name in ("shared", "auth_backend_api"):
            sys.modules.pop(name, None)
        return importlib.import_module("shared")

    return load


@pytest.fixture(params=["", "myapp"], ids=["no-root-path", "root-path"])
def app_module(request, tmp_path, load_shared):
    shared = load_shared(root_path=request.param)
    # Point the DB at a throwaway SQLite file before the app creates its engine.
    shared.DB_URL = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    return importlib.import_module("auth_backend_api")


@pytest.fixture
def client(app_module):
    with TestClient(app_module.app) as client:
        yield client


@pytest.fixture
def prefix(app_module):
    return app_module.root_prefix
