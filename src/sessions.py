import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from fastapi_users import exceptions
from fastapi_users.authentication import JWTStrategy
from fastapi_users.authentication.strategy.db import DatabaseStrategy
from fastapi_users.jwt import decode_jwt, generate_jwt
from sqlalchemy import delete, update

# How long a browser session lasts after signing in. Signing out, resetting or
# changing the password end it earlier.
SESSION_LIFETIME_SECONDS = 14 * 24 * 3600

# Not just "session", a common default (Starlette's SessionMiddleware uses it).
# Under ROOT_PATH the browser also sends the cookies of an app at the domain's
# root, after this one's, and Starlette keeps the last cookie of each name.
# A second copy of this app under this one's path needs another name.
SESSION_COOKIE_NAME = "lowjs_session"

# A session's last use is saved at most this often, not on every request.
LAST_USED_RESOLUTION_SECONDS = 5 * 60

# First match wins: Edge and Opera also say "Chrome", Chrome says "Safari", Android says "Linux".
BROWSERS = (
    ("Edg/", "Edge"), ("OPR/", "Opera"), ("SamsungBrowser/", "Samsung Internet"),
    ("Firefox/", "Firefox"), ("FxiOS/", "Firefox"), ("CriOS/", "Chrome"), ("Chrome/", "Chrome"),
    ("Safari/", "Safari"),
)
SYSTEMS = (
    ("iPhone", "iPhone"), ("iPad", "iPad"), ("Android", "Android"), ("CrOS", "ChromeOS"),
    ("Windows", "Windows"), ("Macintosh", "macOS"), ("Linux", "Linux"),
)


def describe_device(user_agent: str | None) -> str:
    """A name like "Firefox on Linux", to tell sessions apart. Anyone can set the header."""
    user_agent = user_agent or ""
    browser = next((name for marker, name in BROWSERS if marker in user_agent), None)
    system = next((name for marker, name in SYSTEMS if marker in user_agent), None)
    if browser and system:
        return f"{browser} on {system}"
    # Other clients by their name: "curl/8.5.0" is curl.
    return browser or system or user_agent.split("/")[0].strip()[:40] or "Unknown device"


def session_expiry_cutoff(lifetime_seconds: int = SESSION_LIFETIME_SECONDS) -> datetime:
    """Sessions created before this have expired: fastapi-users reads with the same cutoff."""
    return datetime.now(UTC) - timedelta(seconds=lifetime_seconds)


def hash_token(token: str) -> str:
    # SHA-256 is enough: tokens are 256 random bits, not guessable passwords.
    # Base64url without padding is 43 characters, the size of the token column.
    return base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).rstrip(b"=").decode()


class HashedDatabaseStrategy(DatabaseStrategy):
    """fastapi-users' DatabaseStrategy, storing only a hash of each token.

    The cookie carries the token; the database never sees it, so a leaked
    database doesn't hand out working sessions. Each one also keeps its device
    and last use, for the list of signed-in devices.
    """

    def __init__(
        self, database, lifetime_seconds=None, user_agent: str | None = None, ip_address: str | None = None
    ):
        super().__init__(database, lifetime_seconds)
        self.user_agent = user_agent
        self.ip_address = ip_address

    async def read_token(self, token, user_manager):
        # fastapi-users' read_token, with the hash, noting the session's use.
        if not token:
            return None
        max_age = session_expiry_cutoff(self.lifetime_seconds) if self.lifetime_seconds else None
        access_token = await self.database.get_by_token(hash_token(token), max_age)
        if access_token is None:
            return None
        try:
            user = await user_manager.get(user_manager.parse_id(access_token.user_id))
        except (exceptions.UserNotExists, exceptions.InvalidID):
            return None
        await self.record_use(access_token)
        return user

    async def record_use(self, access_token) -> None:
        now = datetime.now(UTC)
        last_used_at = access_token.last_used_at
        if last_used_at and now - last_used_at < timedelta(seconds=LAST_USED_RESOLUTION_SECONDS):
            return
        table = self.database.access_token_table
        # By its key: a session signed out in the meantime just matches no row.
        await self.database.session.execute(
            update(table).where(table.token == access_token.token).values(last_used_at=now)
        )
        await self.database.session.commit()

    async def write_token(self, user) -> str:
        table = self.database.access_token_table
        # Expired sessions are ignored, but nothing else deletes them: each sign-in
        # also sweeps away the user's own. database.create() commits both.
        if self.lifetime_seconds:
            await self.database.session.execute(
                delete(table).where(
                    table.user_id == user.id,
                    table.created_at < session_expiry_cutoff(self.lifetime_seconds),
                )
            )
        token = secrets.token_urlsafe()
        await self.database.create({
            "token": hash_token(token),
            "user_id": user.id,
            # Cut to their columns: they come from the request, and Postgres refuses longer values.
            "user_agent": self.user_agent[:table.user_agent.type.length] if self.user_agent else None,
            "ip_address": self.ip_address[:table.ip_address.type.length] if self.ip_address else None,
        })
        return token

    async def destroy_token(self, token: str, user) -> None:
        await super().destroy_token(hash_token(token), user)


def password_fingerprint(secret: str, hashed_password: str) -> str:
    """A short value that changes whenever the password does, for tokens to carry.

    Keyed with the signing secret, so a token reveals nothing about the hash. A
    plain HMAC, cheap enough to check on every request.
    """
    digest = hmac.new(secret.encode(), b"password:" + hashed_password.encode(), hashlib.sha256)
    return base64.urlsafe_b64encode(digest.digest()[:16]).rstrip(b"=").decode()


class PasswordBoundJWTStrategy(JWTStrategy):
    """fastapi-users' JWTStrategy, with JWTs that stop working when the password changes.

    A JWT can't be revoked, but it can carry a fingerprint of the password hash:
    after a change, a reset or Google taking over an unverified account, it no
    longer matches and the token is refused.
    """

    def fingerprint(self, user) -> str:
        return password_fingerprint(self.secret, user.hashed_password)

    async def write_token(self, user) -> str:
        data = {"sub": str(user.id), "aud": self.token_audience, "pwd": self.fingerprint(user)}
        return generate_jwt(data, self.encode_key, self.lifetime_seconds, algorithm=self.algorithm)

    async def read_token(self, token, user_manager):
        user = await super().read_token(token, user_manager)
        if user is None:
            return None
        try:
            # Already checked by super(); read again for the fingerprint.
            claims = decode_jwt(token, self.decode_key, self.token_audience, algorithms=[self.algorithm])
        except jwt.PyJWTError:  # it expired in between
            return None
        # Tokens from before the password changed, or without a fingerprint at all.
        if not secrets.compare_digest(str(claims.get("pwd", "")), self.fingerprint(user)):
            return None
        return user
