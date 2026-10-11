#!/usr/bin/env python3

import secrets
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi_users import FastAPIUsers, UUIDIDMixin, BaseUserManager, InvalidPasswordException
from fastapi_users.db import SQLAlchemyBaseUserTableUUID
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users.authentication import AuthenticationBackend
from fastapi_users.authentication import BearerTransport
from fastapi_users.authentication import JWTStrategy
from fastapi_sso.sso.google import GoogleSSO

from fastapi_users import schemas

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker

from typing import AsyncGenerator
from fastapi.responses import RedirectResponse

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from shared import DB_URL

from shared import GOOGLE_CLIENT_ID
from shared import GOOGLE_CLIENT_SECRET
from shared import GOOGLE_REDIRECT_URI

from shared import APP_ROOT_PATH

from shared import JWT_SIGNING_SECRET_KEY


if APP_ROOT_PATH != "":
    root_prefix = f"/{APP_ROOT_PATH}"
else:
    root_prefix = ""


# --> CONFIG TEMPLATES:
templates = Jinja2Templates(directory=Path(__file__).parent / "web" / "templates")


# --> USER MODEL:
Base = declarative_base()


class User(SQLAlchemyBaseUserTableUUID, Base):
    pass


# --> DB SETUP:
engine = create_async_engine(DB_URL, future=True)
async_session_maker = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session


async def get_user_db(session: AsyncSession = Depends(get_async_session)):
    yield SQLAlchemyUserDatabase(session, User)


# --> MANAGER:
MIN_PASSWORD_LENGTH = 8


class UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    reset_password_token_secret = JWT_SIGNING_SECRET_KEY
    verification_token_secret = JWT_SIGNING_SECRET_KEY

    async def validate_password(self, password: str, user: "UserCreate | User") -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise InvalidPasswordException(
                reason=f"Password should be at least {MIN_PASSWORD_LENGTH} characters"
            )


# --> USER MANAGER FACTORY:
async def get_user_manager(user_db=Depends(get_user_db)):
    yield UserManager(user_db)

# --> AUTHENTICATION:
# Relative, so Swagger's "Authorize" also works when served under ROOT_PATH.
bearer_transport = BearerTransport(tokenUrl="auth/jwt/login")


def get_jwt_strategy() -> JWTStrategy:
    return JWTStrategy(secret=JWT_SIGNING_SECRET_KEY, lifetime_seconds=3600)


auth_backend = AuthenticationBackend(
    name="jwt",
    transport=bearer_transport,
    get_strategy=get_jwt_strategy
)

# --> FASTAPI USERS:
fastapi_users = FastAPIUsers[User, uuid.UUID](
    get_user_manager,
    [auth_backend],
)

current_active_user = fastapi_users.current_user(active=True)

# --> GOOGLE SSO:
google_sso = GoogleSSO(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    redirect_uri=GOOGLE_REDIRECT_URI
)

# Cookie holding the OAuth "state", only sent back to the callback URL.
GOOGLE_STATE_COOKIE = "google_oauth_state"
google_state_cookie_options = {
    "path": urlsplit(GOOGLE_REDIRECT_URI).path or "/",
    "secure": GOOGLE_REDIRECT_URI.startswith("https://"),
    "httponly": True,
    # "lax" still sends it on the top-level redirect back from Google.
    "samesite": "lax",
}

# --> APP SETUP:
# app = FastAPI()

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(
    lifespan=lifespan,
    root_path=root_prefix,
    title=APP_ROOT_PATH.capitalize() or "FastAPI LowJS Auth",
)


# --> RUTAS JWT (email/pass):
# from fastapi_users.schemas import UserCreate, UserRead


class UserRead(schemas.BaseUser[uuid.UUID]):
    pass


class UserCreate(schemas.BaseUserCreate):
    pass


class UserUpdate(schemas.BaseUserUpdate):  # opcional (para /users router)
    pass


app.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/auth/jwt",
    tags=["auth"]
)
app.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/auth",
    tags=["auth"]
)
app.include_router(
    fastapi_users.get_users_router(UserRead, UserUpdate),
    prefix="/users",
    tags=["users"]
)


# --> TEST ROUTE:
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "base_url": str(request.base_url).rstrip("/"),
            "min_password_length": MIN_PASSWORD_LENGTH,
        }
    )


@app.get("/me")
async def get_me(user: User = Depends(current_active_user)):
    return {"email": user.email, "id": str(user.id)}


# --> GOOGLE LOGIN:
@app.get("/auth/google/login")
async def google_login():
    # A random "state" tied to this browser by a cookie: the callback rejects
    # logins this browser didn't start (login CSRF).
    state = secrets.token_urlsafe(32)
    async with google_sso:
        response = await google_sso.get_login_redirect(state=state)
    response.set_cookie(GOOGLE_STATE_COOKIE, state, max_age=600, **google_state_cookie_options)
    return response


@app.get("/auth/google/callback")
async def google_callback(
    request: Request,
    user_manager: UserManager = Depends(get_user_manager)
        ):
    expected_state = request.cookies.get(GOOGLE_STATE_COOKIE, "")
    state = request.query_params.get("state", "")
    if not expected_state or not secrets.compare_digest(state.encode(), expected_state.encode()):
        raise HTTPException(400, "Invalid OAuth state")

    async with google_sso:
        user_info = await google_sso.verify_and_process(request)

    if user_info is None:
        raise HTTPException(401, "Google login failed")

    # Search or create user. Google only returns verified emails (fastapi-sso
    # rejects the rest), so this login proves the user owns the address.
    user = await user_manager.user_db.get_by_email(user_info.email)
    if not user or not user.is_verified:
        # Google wins: the account becomes verified and gets the hash of a random
        # password. New accounts have no password, and the one of an unverified
        # account may have been set by whoever registered the email first.
        password = user_manager.password_helper.generate()
        google_fields = {
            "hashed_password": user_manager.password_helper.hash(password),
            "is_verified": True,
        }
        if user:
            user = await user_manager.user_db.update(user, google_fields)
        else:
            user = await user_manager.user_db.create({
                "email": user_info.email,
                "is_active": True,
                **google_fields
            })

    # Same token as /auth/jwt/login, including the "aud" claim.
    token = await get_jwt_strategy().write_token(user)

    # The token goes in the fragment, which browsers never send to the server,
    # so it stays out of access logs.
    response = RedirectResponse(f"{root_prefix}/login#token={token}")
    response.delete_cookie(GOOGLE_STATE_COOKIE, **google_state_cookie_options)
    return response
    # return {"access_token": token, "token_type": "bearer"}
