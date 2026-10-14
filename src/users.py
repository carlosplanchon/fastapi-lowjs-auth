import asyncio
import secrets
import uuid
from typing import Annotated

import jwt
from fastapi import BackgroundTasks, Depends, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_users import (
    BaseUserManager,
    InvalidPasswordException,
    UUIDIDMixin,
    exceptions,
    schemas,
)
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users.jwt import decode_jwt, generate_jwt
from sqlalchemy import delete

import mailer
import rate_limits
from database import get_user_db
from models import AccessToken, User
from sessions import password_fingerprint
from shared import APP_PUBLIC_URL, JWT_SIGNING_SECRET_KEY, ROOT_PREFIX

MIN_PASSWORD_LENGTH = 8

# Argon2 takes about 0.2 s and 64 MiB per hash: in threads, two at a time.
HASHING_SLOTS = asyncio.Semaphore(2)


# Built from the configured public URL, never from the request's Host header: a
# forged Host would make the links in emails point to an attacker's site.
LOGIN_URL = f"{APP_PUBLIC_URL}{ROOT_PREFIX}/login"


def email_link(name: str, token: str) -> str:
    return f"{LOGIN_URL}#{name}={token}"


# Changing the email takes two links: one to the current address to approve the
# change, then one to the new address to confirm it.
APPROVE_EMAIL_AUDIENCE = "fastapi-lowjs-auth:approve-email"
CONFIRM_EMAIL_AUDIENCE = "fastapi-lowjs-auth:confirm-email"
EMAIL_CHANGE_LINK_LIFETIME_SECONDS = 3600


def email_change_token(audience: str, user: User, new_email: str) -> str:
    # Bound to the current email and password: the change happens at most once, and
    # changing or resetting the password cancels it. (After A→B and then B→A, an
    # unexpired A→B link would work again: that takes B's mailbox, within the hour.)
    data = {
        "sub": str(user.id),
        "old": user.email,
        "new": new_email,
        "pwd": password_fingerprint(JWT_SIGNING_SECRET_KEY, user.hashed_password),
        "aud": audience,
    }
    return generate_jwt(data, JWT_SIGNING_SECRET_KEY, EMAIL_CHANGE_LINK_LIFETIME_SECONDS)


# What the API returns and accepts for users: fastapi-users' fields.
class UserRead(schemas.BaseUser[uuid.UUID]):
    pass


class UserCreate(schemas.BaseUserCreate):
    pass


class UserUpdate(schemas.BaseUserUpdate):
    pass


class UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    reset_password_token_secret = JWT_SIGNING_SECRET_KEY
    verification_token_secret = JWT_SIGNING_SECRET_KEY

    def __init__(self, user_db: SQLAlchemyUserDatabase, background_tasks: BackgroundTasks):
        super().__init__(user_db)
        # Emails go out after the response: requests don't wait for SMTP, and
        # forgot-password takes as long for unknown emails as for known ones.
        self.background_tasks = background_tasks

    async def validate_password(self, password: str, user: UserCreate | User) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise InvalidPasswordException(
                reason=f"Password should be at least {MIN_PASSWORD_LENGTH} characters"
            )

    # fastapi-users hashes on the event loop, stalling every request: rewritten below to use these.
    async def hash_password(self, password: str) -> str:
        async with HASHING_SLOTS:
            return await asyncio.to_thread(self.password_helper.hash, password)

    async def verify_password(self, password: str, hashed_password: str) -> tuple[bool, str | None]:
        async with HASHING_SLOTS:
            return await asyncio.to_thread(self.password_helper.verify_and_update, password, hashed_password)

    async def authenticate(self, credentials: OAuth2PasswordRequestForm) -> User | None:
        try:
            user = await self.get_by_email(credentials.username)
        except exceptions.UserNotExists:
            # Hashed anyway, so that an unknown email takes as long as a wrong password.
            await self.hash_password(credentials.password)
            return None
        verified, updated_password_hash = await self.verify_password(credentials.password, user.hashed_password)
        if not verified:
            return None
        if updated_password_hash is not None:
            await self.user_db.update(user, {"hashed_password": updated_password_hash})
        return user

    async def create(self, user_create: UserCreate, safe: bool = False, request: Request | None = None) -> User:
        await self.validate_password(user_create.password, user_create)
        if await self.user_db.get_by_email(user_create.email) is not None:
            raise exceptions.UserAlreadyExists()
        user_dict = user_create.create_update_dict() if safe else user_create.create_update_dict_superuser()
        user_dict["hashed_password"] = await self.hash_password(user_dict.pop("password"))
        created_user = await self.user_db.create(user_dict)
        await self.on_after_register(created_user, request)
        return created_user

    async def _update(self, user: User, update_dict: dict) -> User:
        # A new password arrives already hashed: fastapi-users' _update then just stores it.
        if update_dict.get("password") is not None:
            update_dict = dict(update_dict)
            password = update_dict.pop("password")
            await self.validate_password(password, user)
            update_dict["hashed_password"] = await self.hash_password(password)
        return await super()._update(user, update_dict)

    # HMAC fingerprint, as in the JWTs: fastapi-users' Argon2 one slowed down registered emails only.
    async def forgot_password(self, user: User, request: Request | None = None) -> None:
        if not user.is_active:
            raise exceptions.UserInactive()
        data = {
            "sub": str(user.id),
            "password_fgpt": password_fingerprint(JWT_SIGNING_SECRET_KEY, user.hashed_password),
            "aud": self.reset_password_token_audience,
        }
        token = generate_jwt(data, self.reset_password_token_secret, self.reset_password_token_lifetime_seconds)
        await self.on_after_forgot_password(user, token, request)

    async def reset_password(self, token: str, password: str, request: Request | None = None) -> User:
        try:
            data = decode_jwt(token, self.reset_password_token_secret, [self.reset_password_token_audience])
            user = await self.get(self.parse_id(str(data.get("sub", ""))))
        except (jwt.PyJWTError, exceptions.InvalidID):
            raise exceptions.InvalidResetPasswordToken()
        fingerprint = password_fingerprint(JWT_SIGNING_SECRET_KEY, user.hashed_password)
        if not secrets.compare_digest(str(data.get("password_fgpt", "")), fingerprint):
            raise exceptions.InvalidResetPasswordToken()
        if not user.is_active:
            raise exceptions.UserInactive()
        updated_user = await self._update(user, {"password": password})
        await self.on_after_reset_password(user, request)
        return updated_user

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
            f"The link expires in {self.verification_token_lifetime_seconds // 60} minutes. "
            "If you didn't sign up, ignore this email: someone else used your address, "
            "and confirming it would verify their account.\n",
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
        # them the account back: it goes to this same address, which only changes with
        # its own approval.
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
        await self.delete_sessions(user)
        await self.user_db.session.commit()

    async def delete_sessions(self, user: User) -> None:
        # Without committing: for callers that commit it together with their own change.
        await self.user_db.session.execute(delete(AccessToken).where(AccessToken.user_id == user.id))

    async def on_before_delete(self, user: User, request: Request | None = None) -> None:
        # The database would cascade too, but SQLite only does with foreign keys on.
        # No commit: user_db.delete() commits it with the user's row, so a delete that
        # fails changes nothing.
        await self.delete_sessions(user)

    async def on_after_delete(self, user: User, request: Request | None = None) -> None:
        # Verified addresses only: signing up someone else's address and deleting the
        # account over and over would otherwise flood it. Also runs when a superuser
        # deletes an account (DELETE /users/{id}), hence the neutral wording.
        if not user.is_verified:
            return
        self.background_tasks.add_task(
            mailer.send_email,
            user.email,
            "Your account was deleted",
            "Your account and its data were deleted, and every device signed in to it "
            "was signed out. This can't be undone.\n\n"
            f"You can sign up again with this email at any time:\n\n{LOGIN_URL}\n",
        )

    async def email_change_from_link(self, token: str, audience: str) -> tuple[User, str] | None:
        """The user and their new email, if the link is valid and still applies."""
        try:
            claims = decode_jwt(token, JWT_SIGNING_SECRET_KEY, [audience])
            user = await self.get(self.parse_id(str(claims.get("sub", ""))))
        except (jwt.PyJWTError, exceptions.InvalidID, exceptions.UserNotExists):
            return None
        fingerprint = password_fingerprint(JWT_SIGNING_SECRET_KEY, user.hashed_password)
        if (
            not user.is_active
            or user.email != claims.get("old")
            or not secrets.compare_digest(str(claims.get("pwd", "")), fingerprint)
        ):
            return None
        return user, str(claims.get("new", ""))

    def send_email_change_approval(self, user: User, new_email: str) -> None:
        # To the current address: only its owner can move the account elsewhere.
        token = email_change_token(APPROVE_EMAIL_AUDIENCE, user, new_email)
        self.background_tasks.add_task(
            mailer.send_email,
            user.email,
            "Approve your new email",
            f"Someone asked to change the email of your account to {new_email}.\n\n"
            "If it was you, open this link to approve it. We'll then email the new "
            "address a link to confirm it:\n\n"
            f"{email_link('approve_email_token', token)}\n\n"
            f"The link expires in {EMAIL_CHANGE_LINK_LIFETIME_SECONDS // 60} minutes. "
            "If it wasn't you, don't approve it, and change your password: someone else knows it.\n",
        )

    def send_email_change_confirmation(self, user: User, new_email: str) -> None:
        # Nothing about the account's current address: the requester picks who gets this.
        token = email_change_token(CONFIRM_EMAIL_AUDIENCE, user, new_email)
        self.background_tasks.add_task(
            mailer.send_email,
            new_email,
            "Confirm your new email",
            "Open this link to make this the email of your account:\n\n"
            f"{email_link('confirm_email_token', token)}\n\n"
            f"The link expires in {EMAIL_CHANGE_LINK_LIFETIME_SECONDS // 60} minutes. "
            "If you didn't ask for this, ignore this email: confirming would make your "
            "address the email of someone else's account.\n",
        )

    def send_email_changed_notice(self, old_email: str, new_email: str) -> None:
        self.background_tasks.add_task(
            mailer.send_email,
            old_email,
            "Your email was changed",
            f"The email of your account is now {new_email}: sign in with it from now on.\n",
        )

    async def on_after_login(self, user: User, request: Request | None = None, response=None) -> None:
        if request is not None:
            await rate_limits.login_succeeded(request, user.email)


async def get_user_manager(
    background_tasks: BackgroundTasks,
    user_db: Annotated[SQLAlchemyUserDatabase, Depends(get_user_db)],
):
    yield UserManager(user_db, background_tasks)


UserManagerDep = Annotated[UserManager, Depends(get_user_manager)]
