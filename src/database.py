from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users_db_sqlalchemy.access_token import SQLAlchemyAccessTokenDatabase
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from models import AccessToken, User
from shared import DB_URL

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
