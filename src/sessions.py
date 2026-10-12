import base64
import hashlib
import hmac
import secrets

import jwt
from fastapi_users.authentication import JWTStrategy
from fastapi_users.authentication.strategy.db import DatabaseStrategy
from fastapi_users.jwt import decode_jwt, generate_jwt

# How long a browser session lasts after signing in. Signing out, resetting or
# changing the password end it earlier.
SESSION_LIFETIME_SECONDS = 14 * 24 * 3600


def hash_token(token: str) -> str:
    # SHA-256 is enough: tokens are 256 random bits, not guessable passwords.
    # Base64url without padding is 43 characters, the size of the token column.
    return base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).rstrip(b"=").decode()


class HashedDatabaseStrategy(DatabaseStrategy):
    """fastapi-users' DatabaseStrategy, storing only a hash of each token.

    The cookie carries the token; the database never sees it, so a leaked
    database doesn't hand out working sessions.
    """

    async def read_token(self, token, user_manager):
        return await super().read_token(hash_token(token) if token else None, user_manager)

    async def write_token(self, user) -> str:
        token = secrets.token_urlsafe()
        await self.database.create({"token": hash_token(token), "user_id": user.id})
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
