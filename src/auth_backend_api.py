import logging
import secrets
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi_sso.sso.google import GoogleSSO
from fastapi_users import (
    BaseUserManager,
    FastAPIUsers,
    InvalidPasswordException,
    UUIDIDMixin,
    schemas,
)
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport,
    CookieTransport,
)
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users_db_sqlalchemy.access_token import SQLAlchemyAccessTokenDatabase
from pydantic import BaseModel
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

import mailer
import rate_limits
from models import AccessToken, User
from origin_check import OriginCheckMiddleware
from security_headers import SecurityHeadersMiddleware
from sessions import (
    SESSION_LIFETIME_SECONDS,
    HashedDatabaseStrategy,
    PasswordBoundJWTStrategy,
)
from shared import (
    APP_PUBLIC_URL,
    APP_ROOT_PATH,
    DB_URL,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
    JWT_SIGNING_SECRET_KEY,
)

if APP_ROOT_PATH != "":
    root_prefix = f"/{APP_ROOT_PATH}"
else:
    root_prefix = ""


# --> CONFIG TEMPLATES:
templates = Jinja2Templates(directory=Path(__file__).parent / "web" / "templates")


# --> DB SETUP:
# The tables come from the Alembic migrations (src/migrations): uv run alembic upgrade head
engine = create_async_engine(DB_URL, future=True)
async_session_maker = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)


async def get_async_session() -> AsyncGenerator[AsyncSession]:
    async with async_session_maker() as session:
        yield session


# One per request: everything that depends on it shares the same session.
AsyncSessionDep = Annotated[AsyncSession, Depends(get_async_session)]


async def get_user_db(session: AsyncSessionDep):
    yield SQLAlchemyUserDatabase(session, User)


async def get_access_token_db(session: AsyncSessionDep):
    yield SQLAlchemyAccessTokenDatabase(session, AccessToken)


# --> MANAGER:
MIN_PASSWORD_LENGTH = 8


# Built from the configured public URL, never from the request's Host header: a
# forged Host would make the links in emails point to an attacker's site.
LOGIN_URL = f"{APP_PUBLIC_URL}{root_prefix}/login"


def email_link(name: str, token: str) -> str:
    return f"{LOGIN_URL}#{name}={token}"


class UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    reset_password_token_secret = JWT_SIGNING_SECRET_KEY
    verification_token_secret = JWT_SIGNING_SECRET_KEY

    def __init__(self, user_db: SQLAlchemyUserDatabase, background_tasks: BackgroundTasks):
        super().__init__(user_db)
        # Emails go out after the response: requests don't wait for SMTP, and
        # forgot-password takes as long for unknown emails as for known ones.
        self.background_tasks = background_tasks

    async def validate_password(self, password: str, user: "UserCreate | User") -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise InvalidPasswordException(
                reason=f"Password should be at least {MIN_PASSWORD_LENGTH} characters"
            )

    async def on_after_register(self, user: User, request: Request | None = None) -> None:
        if not user.is_verified:
            await self.request_verify(user, request)

    async def on_after_request_verify(self, user: User, token: str, request: Request | None = None) -> None:
        self.background_tasks.add_task(
            mailer.send_email,
            user.email,
            "Verify your email",
            "Confirm your email address by opening this link:\n\n"
            f"{email_link('verify_token', token)}\n\n"
            f"The link expires in {self.verification_token_lifetime_seconds // 60} minutes.\n",
        )

    async def on_after_forgot_password(self, user: User, token: str, request: Request | None = None) -> None:
        self.background_tasks.add_task(
            mailer.send_email,
            user.email,
            "Reset your password",
            "Choose a new password by opening this link:\n\n"
            f"{email_link('reset_token', token)}\n\n"
            f"The link expires in {self.reset_password_token_lifetime_seconds // 60} minutes. "
            "If you didn't ask to reset your password, you can ignore this email.\n",
        )

    async def on_after_reset_password(self, user: User, request: Request | None = None) -> None:
        # The reset link was sent to the account's email, so using it proves the
        # user owns the address.
        if not user.is_verified:
            await self.user_db.update(user, {"is_verified": True})
        # Whoever knew the old password may have a session: end them all.
        await self.end_all_sessions(user)
        self.send_password_changed_email(user)

    async def on_after_update(self, user: User, update_dict: dict, request: Request | None = None) -> None:
        if "password" in update_dict:
            await self.end_all_sessions(user)
            self.send_password_changed_email(user)

    def send_password_changed_email(self, user: User) -> None:
        # The owner hears about every change. If it wasn't them, a reset link gives
        # them the account back: it goes to this same address, which can't be changed.
        self.background_tasks.add_task(
            mailer.send_email,
            user.email,
            "Your password was changed",
            "The password of your account was just changed.\n\n"
            "If it was you, you can ignore this email. If it wasn't, someone else may have "
            "access to your account: choose a new password right away with "
            "\"Forgot your password?\" on the sign-in page.\n\n"
            f"{LOGIN_URL}\n",
        )

    async def end_all_sessions(self, user: User) -> None:
        # Browser sessions only. Bearer JWTs stop working by themselves when the
        # password changes (PasswordBoundJWTStrategy), and otherwise expire within the hour.
        await self.user_db.session.execute(delete(AccessToken).where(AccessToken.user_id == user.id))
        await self.user_db.session.commit()

    async def on_after_login(self, user: User, request: Request | None = None, response=None) -> None:
        if request is not None:
            await rate_limits.login_succeeded(request, user.email)


# --> USER MANAGER FACTORY:
async def get_user_manager(
    background_tasks: BackgroundTasks,
    user_db: Annotated[SQLAlchemyUserDatabase, Depends(get_user_db)],
):
    yield UserManager(user_db, background_tasks)


UserManagerDep = Annotated[UserManager, Depends(get_user_manager)]

# --> AUTHENTICATION:
# Browsers: an HttpOnly session cookie (JavaScript can't read it) backed by a row
# in the database, so signing out really ends the session.
cookie_transport = CookieTransport(
    cookie_name="session",
    cookie_max_age=SESSION_LIFETIME_SECONDS,
    cookie_path=root_prefix or "/",
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

# --> FASTAPI USERS:
fastapi_users = FastAPIUsers[User, uuid.UUID](
    get_user_manager,
    [cookie_backend, jwt_backend],
)

current_active_user = fastapi_users.current_user(active=True)
CurrentUser = Annotated[User, Depends(current_active_user)]
# The user and the token they signed in with: tells the session cookie from a Bearer JWT.
current_active_user_and_token = fastapi_users.authenticator.current_user_token(active=True)
CurrentUserAndToken = Annotated[tuple[User, str], Depends(current_active_user_and_token)]

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
    yield
    await engine.dispose()


app = FastAPI(
    lifespan=lifespan,
    root_path=root_prefix,
    title=APP_ROOT_PATH.capitalize() or "FastAPI LowJS Auth",
)

class RevalidatedStaticFiles(StaticFiles):
    # Without Cache-Control, browsers guess from Last-Modified how long a file stays
    # fresh and reuse it without asking: after a deploy, the new page could run with
    # an old app.js. no-cache makes them check first (a 304 when nothing changed).
    def file_response(self, *args, **kwargs) -> Response:
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


# Compiled Tailwind CSS (build_css.sh) and the pinned Alpine.js build.
app.mount("/static", RevalidatedStaticFiles(directory=Path(__file__).parent / "web" / "static"), name="static")

# Second layer against CSRF: the session cookie is already SameSite=Lax.
app.add_middleware(OriginCheckMiddleware, public_url=APP_PUBLIC_URL)
# Added last, so it wraps everything: even the responses above get the headers.
app.add_middleware(SecurityHeadersMiddleware, https=APP_PUBLIC_URL.startswith("https://"))


# --> RUTAS JWT (email/pass):
# from fastapi_users.schemas import UserCreate, UserRead


class UserRead(schemas.BaseUser[uuid.UUID]):
    pass


class UserCreate(schemas.BaseUserCreate):
    pass


class UserUpdate(schemas.BaseUserUpdate):  # opcional (para /users router)
    pass


# Sign-in, registration and the routes that send emails are rate limited
# (rate_limits.py picks the limits for each route).
app.include_router(
    fastapi_users.get_auth_router(cookie_backend),
    prefix="/auth/cookie",
    tags=["auth"],
    dependencies=[Depends(rate_limits.enforce)]
)
app.include_router(
    fastapi_users.get_auth_router(jwt_backend),
    prefix="/auth/jwt",
    tags=["auth"],
    dependencies=[Depends(rate_limits.enforce)]
)
app.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/auth",
    tags=["auth"],
    dependencies=[Depends(rate_limits.enforce)]
)
app.include_router(
    fastapi_users.get_reset_password_router(),
    prefix="/auth",
    tags=["auth"],
    dependencies=[Depends(rate_limits.enforce)]
)
app.include_router(
    fastapi_users.get_verify_router(UserRead),
    prefix="/auth",
    tags=["auth"],
    dependencies=[Depends(rate_limits.enforce)]
)
# Without PATCH /users/me: it changed the password without asking for the current
# one, and the email without confirming it (a new email plus "forgot password"
# hands the account over). Passwords change through /auth/change-password.
# Removed before include_router, which copies the routes.
users_router = fastapi_users.get_users_router(UserRead, UserUpdate)
patch_me = [route for route in users_router.routes if route.name == "users:patch_current_user"]
if len(patch_me) != 1:
    # A fastapi-users update renamed it: better not to start than to expose it again.
    raise RuntimeError("Can't find fastapi-users' PATCH /users/me route to remove it")
users_router.routes.remove(patch_me[0])
app.include_router(users_router, prefix="/users", tags=["users"])


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
async def get_me(user: CurrentUser):
    return {"email": user.email, "id": str(user.id), "is_verified": user.is_verified}


# --> SESSIONS:
async def renew_this_session(request: Request, token: str, user: User, strategy: HashedDatabaseStrategy) -> Response:
    """For after ending every session of the account: this browser carries on."""
    if token == request.cookies.get(cookie_transport.cookie_name):
        # Signed in with the session cookie: a new session, so that a copy of the
        # old cookie doesn't keep working.
        return await cookie_transport.get_login_response(await strategy.write_token(user))
    # Signed in with a Bearer JWT: there's no session to renew.
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post(
    "/auth/cookie/logout-others",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    name="auth:cookie.logout_others",
    tags=["auth"],
)
async def logout_other_devices(
    request: Request,
    user_and_token: CurrentUserAndToken,
    user_manager: UserManagerDep,
    strategy: SessionStrategyDep,
):
    # Every session ends, this one too, in case someone has a copy of this
    # browser's cookie. Then this browser gets a new one.
    user, token = user_and_token
    await user_manager.end_all_sessions(user)
    return await renew_this_session(request, token, user, strategy)


# --> PASSWORD CHANGE:
class PasswordChange(BaseModel):
    current_password: str
    new_password: str


@app.post(
    "/auth/change-password",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    name="auth:change_password",
    tags=["auth"],
)
async def change_password(
    request: Request,
    body: PasswordChange,
    user_and_token: CurrentUserAndToken,
    user_manager: UserManagerDep,
    strategy: SessionStrategyDep,
):
    user, token = user_and_token
    # Counted before checking: once blocked, even the right password gets a 429,
    # so the answer doesn't tell whether a guess was right.
    await rate_limits.password_change_attempted(user.id)
    verified, _ = user_manager.password_helper.verify_and_update(body.current_password, user.hashed_password)
    if not verified:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "CHANGE_PASSWORD_BAD_CREDENTIALS")
    await rate_limits.password_change_succeeded(user.id)

    try:
        # on_after_update ends every session of the account, this one included.
        user = await user_manager.update(UserUpdate(password=body.new_password), user, safe=True, request=request)
    except InvalidPasswordException as e:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            {"code": "CHANGE_PASSWORD_INVALID_PASSWORD", "reason": e.reason},
        )

    # After the update, so that the new session isn't ended too.
    return await renew_this_session(request, token, user, strategy)


# --> GOOGLE LOGIN:
logger = logging.getLogger(__name__)


def back_to_login(error: str | None = None) -> RedirectResponse:
    # An error goes in the fragment, for the page to show. The state cookie is
    # single use.
    response = RedirectResponse(f"{root_prefix}/login" + (f"#error={error}" if error else ""))
    response.delete_cookie(GOOGLE_STATE_COOKIE, **google_state_cookie_options)
    return response


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
    user_manager: UserManagerDep,
    strategy: SessionStrategyDep,
        ):
    expected_state = request.cookies.get(GOOGLE_STATE_COOKIE, "")
    state = request.query_params.get("state", "")
    if not expected_state or not secrets.compare_digest(state.encode(), expected_state.encode()):
        return back_to_login("GOOGLE_FAILED")

    # Google comes back with ?error=... instead of a code when the user cancels.
    if "error" in request.query_params:
        return back_to_login("GOOGLE_CANCELLED")

    try:
        async with google_sso:
            user_info = await google_sso.verify_and_process(request)
    except Exception:
        # An expired code, an email Google hasn't verified, a network error...
        logger.exception("Google sign-in failed")
        return back_to_login("GOOGLE_FAILED")

    if user_info is None:
        return back_to_login("GOOGLE_FAILED")

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

    # The same session cookie as /auth/cookie/login.
    response = back_to_login()
    login_response = await cookie_transport.get_login_response(await strategy.write_token(user))
    for cookie in login_response.headers.getlist("set-cookie"):
        response.headers.append("set-cookie", cookie)
    await user_manager.on_after_login(user, request, response)
    return response
