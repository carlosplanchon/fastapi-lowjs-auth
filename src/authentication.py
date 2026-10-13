import uuid
from typing import Annotated

from fastapi import Depends, Request, Response, status
from fastapi_users import FastAPIUsers
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport,
    CookieTransport,
)
from fastapi_users_db_sqlalchemy.access_token import SQLAlchemyAccessTokenDatabase

from database import get_access_token_db
from models import User
from sessions import (
    SESSION_COOKIE_NAME,
    SESSION_LIFETIME_SECONDS,
    HashedDatabaseStrategy,
    PasswordBoundJWTStrategy,
)
from shared import APP_PUBLIC_URL, JWT_SIGNING_SECRET_KEY, ROOT_PREFIX
from users import get_user_manager

# Browsers: an HttpOnly session cookie (JavaScript can't read it) backed by a row
# in the database, so signing out really ends the session.
cookie_transport = CookieTransport(
    cookie_name=SESSION_COOKIE_NAME,
    cookie_max_age=SESSION_LIFETIME_SECONDS,
    cookie_path=ROOT_PREFIX or "/",
    cookie_secure=APP_PUBLIC_URL.startswith("https://"),
    cookie_httponly=True,
    cookie_samesite="lax",
)


def get_database_strategy(
    access_token_db: Annotated[SQLAlchemyAccessTokenDatabase, Depends(get_access_token_db)],
) -> HashedDatabaseStrategy:
    return HashedDatabaseStrategy(access_token_db, lifetime_seconds=SESSION_LIFETIME_SECONDS)


SessionStrategyDep = Annotated[HashedDatabaseStrategy, Depends(get_database_strategy)]


cookie_backend = AuthenticationBackend(
    name="cookie",
    transport=cookie_transport,
    get_strategy=get_database_strategy
)

# API clients (scripts, mobile apps, Swagger's "Authorize"): Bearer JWTs. They stop
# working when the password changes, but can't be revoked otherwise (signing out
# doesn't end them), so they're short-lived.
# Relative, so Swagger's "Authorize" also works when served under ROOT_PATH.
bearer_transport = BearerTransport(tokenUrl="auth/jwt/login")


def get_jwt_strategy() -> PasswordBoundJWTStrategy:
    return PasswordBoundJWTStrategy(secret=JWT_SIGNING_SECRET_KEY, lifetime_seconds=3600)


jwt_backend = AuthenticationBackend(
    name="jwt",
    transport=bearer_transport,
    get_strategy=get_jwt_strategy
)

fastapi_users = FastAPIUsers[User, uuid.UUID](
    get_user_manager,
    [cookie_backend, jwt_backend],
)

current_active_user = fastapi_users.current_user(active=True)
CurrentUser = Annotated[User, Depends(current_active_user)]
# The user and the token they signed in with: tells the session cookie from a Bearer JWT.
current_active_user_and_token = fastapi_users.authenticator.current_user_token(active=True)
CurrentUserAndToken = Annotated[tuple[User, str], Depends(current_active_user_and_token)]


async def renew_this_session(request: Request, token: str, user: User, strategy: HashedDatabaseStrategy) -> Response:
    """For after ending every session of the account: this browser carries on."""
    if token == request.cookies.get(cookie_transport.cookie_name):
        # Signed in with the session cookie: a new session, so that a copy of the
        # old cookie doesn't keep working.
        return await cookie_transport.get_login_response(await strategy.write_token(user))
    # Signed in with a Bearer JWT: there's no session to renew.
    return Response(status_code=status.HTTP_204_NO_CONTENT)
