from datetime import datetime

from fastapi_users.db import SQLAlchemyBaseUserTableUUID
from fastapi_users_db_sqlalchemy.access_token import SQLAlchemyBaseAccessTokenTableUUID
from fastapi_users_db_sqlalchemy.generics import TIMESTAMPAware, now_utc
from sqlalchemy import MetaData, String
from sqlalchemy.orm import Mapped, declarative_base, mapped_column

# Predictable constraint names, so later migrations can refer to them
# (Alembic's recommended convention).
Base = declarative_base(metadata=MetaData(naming_convention={
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}))


class User(SQLAlchemyBaseUserTableUUID, Base):
    pass


class AccessToken(SQLAlchemyBaseAccessTokenTableUUID, Base):
    """A browser session: the hash of its cookie's token (see sessions.py)."""

    # For the list of signed-in devices. Empty in sessions from before it.
    user_agent: Mapped[str | None] = mapped_column(String(length=255))
    ip_address: Mapped[str | None] = mapped_column(String(length=45))
    last_used_at: Mapped[datetime | None] = mapped_column(TIMESTAMPAware(timezone=True), default=now_utc)
