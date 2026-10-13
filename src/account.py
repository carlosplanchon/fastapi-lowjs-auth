from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi_users import InvalidPasswordException
from pydantic import BaseModel, EmailStr
from sqlalchemy.exc import IntegrityError

import rate_limits
from authentication import (
    CurrentUser,
    CurrentUserAndToken,
    SessionStrategyDep,
    cookie_transport,
    renew_this_session,
)
from models import User
from users import (
    APPROVE_EMAIL_AUDIENCE,
    CONFIRM_EMAIL_AUDIENCE,
    UserManager,
    UserManagerDep,
    UserUpdate,
)

# The account page's routes: sign out of other devices, change the password,
# delete the account, change the email.
router = APIRouter(tags=["auth"])


# --> SESSIONS:
@router.post(
    "/auth/cookie/logout-others",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    name="auth:cookie.logout_others",
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


# --> CURRENT PASSWORD CHECKS (password change, account deletion, email change):
async def check_current_password(user_manager: UserManager, user: User, password: str, error: str) -> None:
    # Counted before checking: once blocked, even the right password gets a 429,
    # so the answer doesn't tell whether a guess was right.
    await rate_limits.current_password_attempted(user.id)
    verified, _ = user_manager.password_helper.verify_and_update(password, user.hashed_password)
    if not verified:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, error)
    await rate_limits.current_password_succeeded(user.id)


# --> PASSWORD CHANGE:
class PasswordChange(BaseModel):
    current_password: str
    new_password: str


@router.post(
    "/auth/change-password",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    name="auth:change_password",
)
async def change_password(
    request: Request,
    body: PasswordChange,
    user_and_token: CurrentUserAndToken,
    user_manager: UserManagerDep,
    strategy: SessionStrategyDep,
):
    user, token = user_and_token
    await check_current_password(user_manager, user, body.current_password, "CHANGE_PASSWORD_BAD_CREDENTIALS")

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


# --> ACCOUNT DELETION:
class AccountDeletion(BaseModel):
    password: str


@router.post(
    "/auth/delete-account",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    name="auth:delete_account",
)
async def delete_account(request: Request, body: AccountDeletion, user: CurrentUser, user_manager: UserManagerDep):
    await check_current_password(user_manager, user, body.password, "DELETE_ACCOUNT_BAD_CREDENTIALS")
    # The hooks end every session and email the owner.
    await user_manager.delete(user, request=request)
    # The cookie is read before a Bearer token: if this request carried a live
    # one, it was this account's.
    return await cookie_transport.get_logout_response()


# --> EMAIL CHANGE:
class EmailChangeRequest(BaseModel):
    new_email: EmailStr
    password: str


class EmailChangeLink(BaseModel):
    token: str


@router.post(
    "/auth/request-email-change",
    status_code=status.HTTP_202_ACCEPTED,
    response_class=Response,
    name="auth:request_email_change",
)
async def request_email_change(
    request: Request, body: EmailChangeRequest, user: CurrentUser, user_manager: UserManagerDep
):
    await check_current_password(user_manager, user, body.password, "CHANGE_EMAIL_BAD_CREDENTIALS")
    # Before the checks below, so that they can't be used to probe many addresses.
    await rate_limits.email_requested(request, user.email)
    if rate_limits.normalize(body.new_email) == rate_limits.normalize(user.email):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "CHANGE_EMAIL_SAME_EMAIL")
    if await user_manager.user_db.get_by_email(body.new_email) is not None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "CHANGE_EMAIL_ALREADY_EXISTS")
    # Even when the current address isn't verified: without this step, anyone with
    # the password could move the account and leave its owner no way back.
    user_manager.send_email_change_approval(user, body.new_email)
    return Response(status_code=status.HTTP_202_ACCEPTED)


@router.post("/auth/approve-email-change", name="auth:approve_email_change")
async def approve_email_change(request: Request, body: EmailChangeLink, user_manager: UserManagerDep):
    # No session needed: the link proves access to the current address.
    found = await user_manager.email_change_from_link(body.token, APPROVE_EMAIL_AUDIENCE)
    if found is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "CHANGE_EMAIL_BAD_TOKEN")
    user, new_email = found
    # Approving again resends the confirmation: limited like any other email.
    await rate_limits.email_requested(request, new_email)
    if await user_manager.user_db.get_by_email(new_email) is not None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "CHANGE_EMAIL_ALREADY_EXISTS")
    user_manager.send_email_change_confirmation(user, new_email)
    return {"email": new_email}


@router.post("/auth/confirm-email-change", name="auth:confirm_email_change")
async def confirm_email_change(body: EmailChangeLink, user_manager: UserManagerDep):
    found = await user_manager.email_change_from_link(body.token, CONFIRM_EMAIL_AUDIENCE)
    if found is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "CHANGE_EMAIL_BAD_TOKEN")
    user, new_email = found
    old_email = user.email
    if await user_manager.user_db.get_by_email(new_email) is not None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "CHANGE_EMAIL_ALREADY_EXISTS")
    try:
        # Not user_manager.update(): it would mark the account unverified, and this
        # link just proved the new address. Sessions and Bearer tokens stay.
        await user_manager.user_db.update(user, {"email": new_email, "is_verified": True})
    except IntegrityError:  # someone signed up with it in the meantime
        await user_manager.user_db.session.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "CHANGE_EMAIL_ALREADY_EXISTS")
    # The old address approved the change; it only gets the news.
    user_manager.send_email_changed_notice(old_email, new_email)
    return {"email": new_email}
