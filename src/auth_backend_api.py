from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete

import account
import database
import google_sign_in
import rate_limits
import users
from authentication import CurrentUser, cookie_backend, fastapi_users, jwt_backend
from models import AccessToken
from origin_check import OriginCheckMiddleware
from security_headers import SecurityHeadersMiddleware
from sessions import session_expiry_cutoff
from shared import APP_PUBLIC_URL, APP_ROOT_PATH, ROOT_PREFIX

templates = Jinja2Templates(directory=Path(__file__).parent / "web" / "templates")


async def delete_expired_sessions() -> None:
    """Every expired session, whoever's: sign-ins only sweep their own user's."""
    async with database.async_session_maker() as session:
        await session.execute(delete(AccessToken).where(AccessToken.created_at < session_expiry_cutoff()))
        await session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # On every start, and so on every deploy: catches the users who never sign in again.
    await delete_expired_sessions()
    yield
    await database.engine.dispose()


app = FastAPI(
    lifespan=lifespan,
    root_path=ROOT_PREFIX,
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


# --> FASTAPI-USERS ROUTES:
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
    fastapi_users.get_register_router(users.UserRead, users.UserCreate),
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
    fastapi_users.get_verify_router(users.UserRead),
    prefix="/auth",
    tags=["auth"],
    dependencies=[Depends(rate_limits.enforce)]
)
# Without PATCH /users/me: it changed the password without asking for the current
# one, and the email without confirming it (a new email plus "forgot password"
# hands the account over). Passwords change through /auth/change-password.
# Removed before include_router, which copies the routes.
users_router = fastapi_users.get_users_router(users.UserRead, users.UserUpdate)
patch_me = [route for route in users_router.routes if route.name == "users:patch_current_user"]
if len(patch_me) != 1:
    # A fastapi-users update renamed it: better not to start than to expose it again.
    raise RuntimeError("Can't find fastapi-users' PATCH /users/me route to remove it")
users_router.routes.remove(patch_me[0])
app.include_router(users_router, prefix="/users", tags=["users"])


# --> PAGES:
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "base_url": str(request.base_url).rstrip("/"),
            "min_password_length": users.MIN_PASSWORD_LENGTH,
        }
    )


@app.get("/me")
async def get_me(user: CurrentUser):
    return {"email": user.email, "id": str(user.id), "is_verified": user.is_verified}


# --> THE ACCOUNT PAGE AND GOOGLE SIGN-IN:
app.include_router(account.router)
app.include_router(google_sign_in.router)
