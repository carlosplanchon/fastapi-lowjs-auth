#!/usr/bin/env python3

import base64
import hashlib
import secrets

from fastapi_users.authentication.strategy.db import DatabaseStrategy


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
