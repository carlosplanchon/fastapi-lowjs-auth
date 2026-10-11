#!/usr/bin/env python3

import os
from pathlib import Path

import tomllib

from sqlalchemy import URL


##################
# --- CONFIG --- #
##################
# config.toml next to this file; CONFIG_PATH overrides it (used by the tests).
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", Path(__file__).parent / "config.toml"))

with CONFIG_PATH.open(mode="rb") as fp:
    CONFIG = tomllib.load(fp)


DB_USERNAME: str = CONFIG["database"]["DB_USERNAME"]
DB_PASSWORD: str = CONFIG["database"]["DB_PASSWORD"]
DB_HOST: str = CONFIG["database"]["DB_HOST"]
DB_PORT: int = CONFIG["database"]["DB_PORT"]
DB_NAME: str = CONFIG["database"]["DB_NAME"]

# URL.create escapes the credentials, so a password with "@", "/" or "#" still works.
DB_URL: URL = URL.create(
    "postgresql+asyncpg",
    username=DB_USERNAME,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=DB_PORT,
    database=DB_NAME,
)

# used to sign JWTs, make sure it is really secret.
JWT_SIGNING_SECRET_KEY = CONFIG["security"]["JWT_SIGNING_SECRET_KEY"]

GOOGLE_CLIENT_ID = CONFIG["google"]["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = CONFIG["google"]["GOOGLE_CLIENT_SECRET"]
GOOGLE_REDIRECT_URI = CONFIG["google"]["GOOGLE_REDIRECT_URI"]

APP_ROOT_PATH = CONFIG["app"]["ROOT_PATH"]
