import logging
import secrets
from urllib.parse import urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi_sso.sso.google import GoogleSSO

from authentication import SessionStrategyDep, cookie_transport
from shared import (
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
    ROOT_PREFIX,
)
from users import UserManagerDep

logger = logging.getLogger(__name__)

google_sso = GoogleSSO(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    redirect_uri=GOOGLE_REDIRECT_URI
)

# Cookie holding the OAuth "state", only sent back to the callback URL. A name of
# its own, like the session cookie's (see SESSION_COOKIE_NAME).
GOOGLE_STATE_COOKIE = "lowjs_google_state"
google_state_cookie_options = {
    "path": urlsplit(GOOGLE_REDIRECT_URI).path or "/",
    "secure": GOOGLE_REDIRECT_URI.startswith("https://"),
    "httponly": True,
    # "lax" still sends it on the top-level redirect back from Google.
    "samesite": "lax",
}

router = APIRouter()


def back_to_login(error: str | None = None) -> RedirectResponse:
    # An error goes in the fragment, for the page to show. The state cookie is
    # single use.
    response = RedirectResponse(f"{ROOT_PREFIX}/login" + (f"#error={error}" if error else ""))
    response.delete_cookie(GOOGLE_STATE_COOKIE, **google_state_cookie_options)
    return response


@router.get("/auth/google/login")
async def google_login():
    # A random "state" tied to this browser by a cookie: the callback rejects
    # logins this browser didn't start (login CSRF).
    state = secrets.token_urlsafe(32)
    async with google_sso:
        response = await google_sso.get_login_redirect(state=state)
    response.set_cookie(GOOGLE_STATE_COOKIE, state, max_age=600, **google_state_cookie_options)
    return response


@router.get("/auth/google/callback")
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
            # Whoever set that password may still be signed in: end their sessions.
            # No commit: user_db.update() commits it with the takeover, so both
            # happen or neither does.
            await user_manager.delete_sessions(user)
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
