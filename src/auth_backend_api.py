#!/usr/bin/env python3

import uuid
from pathlib import Path

from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi_users import FastAPIUsers, UUIDIDMixin, BaseUserManager
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
class UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    reset_password_token_secret = JWT_SIGNING_SECRET_KEY
    verification_token_secret = JWT_SIGNING_SECRET_KEY


# --> USER MANAGER FACTORY:
async def get_user_manager(user_db=Depends(get_user_db)):
    yield UserManager(user_db)

# --> AUTHENTICATION:
bearer_transport = BearerTransport(tokenUrl="/auth/jwt/login")


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

# --> APP SETUP:
# app = FastAPI()

app = FastAPI(
    # lifespan=lifespan,
    root_path=root_prefix,
    title=APP_ROOT_PATH.capitalize() or "FastAPI LowJS Auth",
)


@app.on_event("startup")
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


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
        "login.html",
        {
            "request": request,
            "base_url": str(request.base_url).rstrip("/"),
        }
    )


@app.get("/me")
async def get_me(user: User = Depends(current_active_user)):
    return {"email": user.email, "id": str(user.id)}


# --> GOOGLE LOGIN:
@app.get("/auth/google/login")
async def google_login():
    async with google_sso:
        return await google_sso.get_login_redirect()


@app.get("/auth/google/callback")
async def google_callback(
    request: Request,
    user_manager: UserManager = Depends(get_user_manager)
        ):
    async with google_sso:
        user_info = await google_sso.verify_and_process(request)

    if user_info is None:
        raise HTTPException(401, "Google login failed")

    # Search or create user:
    user = await user_manager.user_db.get_by_email(user_info.email)
    if not user:
        # Google users have no local password: store the hash of a random one,
        # as fastapi-users' own OAuth callback does.
        password = user_manager.password_helper.generate()
        user = await user_manager.user_db.create({
            "email": user_info.email,
            "hashed_password": user_manager.password_helper.hash(password),
            "is_active": True
        })

    # Same token as /auth/jwt/login, including the "aud" claim.
    token = await get_jwt_strategy().write_token(user)

    return RedirectResponse(f"{root_prefix}/login?token={token}")
    # return {"access_token": token, "token_type": "bearer"}
