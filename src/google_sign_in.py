import logging
import secrets
import time
from urllib.parse import urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi_sso.sso.base import DiscoveryDocument
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

# Google lets clients keep its discovery document for an hour (Cache-Control: max-age=3600).
DISCOVERY_MAX_AGE_SECONDS = 3600
discovery_cache: dict = {}


class CachingGoogleSSO(GoogleSSO):
    """fastapi-sso's GoogleSSO, fetching Google's discovery document once an hour, not three times per sign-in."""

    async def get_discovery_document(self) -> DiscoveryDocument:
        if time.monotonic() < discovery_cache.get("expires_at", 0):
            return discovery_cache["document"]
        document = await super().get_discovery_document()
        if {"authorization_endpoint", "token_endpoint", "userinfo_endpoint"} <= document.keys():
            discovery_cache.update(document=document, expires_at=time.monotonic() + DISCOVERY_MAX_AGE_SECONDS)
        return document


def google_sso() -> CachingGoogleSSO:
    # One per request: fastapi-sso locks it for a whole sign-in, Google's answers included.
    return CachingGoogleSSO(
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
    try:
        async with google_sso() as sso:
            response = await sso.get_login_redirect(state=state)
    except Exception:
        # Google's discovery document out of reach.
        logger.exception("Google sign-in failed")
        return back_to_login("GOOGLE_FAILED")
    # Without fastapi-sso's own state cookie (sso_state), which goes to the whole domain.
    del response.headers["set-cookie"]
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
    code = request.query_params.get("code")
    if not code:
        return back_to_login("GOOGLE_FAILED")

    try:
        async with google_sso() as sso:
            # Not verify_and_process(): it checks the state against fastapi-sso's own cookie.
            user_info = await sso.process_login(code, request)
    except Exception:
        # An expired code, an email Google hasn't verified, a network error...
        logger.exception("Google sign-in failed")
        return back_to_login("GOOGLE_FAILED")

    if user_info is None:
        return back_to_login("GOOGLE_FAILED")

    # Search or create user. Google only returns verified emails (fastapi-sso
    # rejects the rest), so this login proves the user owns the address.
    user = await user_manager.user_db.get_by_email(user_info.email)
    # A new account, or one Google takes over: nobody else to tell about this sign-in.
    claimed = not user or not user.is_verified
    if claimed:
        # Google wins: the account becomes verified and gets the hash of a random
        # password. New accounts have no password, and the one of an unverified
        # account may have been set by whoever registered the email first.
        password = user_manager.password_helper.generate()
        google_fields = {
            "hashed_password": await user_manager.hash_password(password),
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
    await user_manager.on_after_login(user, request, response, with_google=True, announce=not claimed)
    return response
