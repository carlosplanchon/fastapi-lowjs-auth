#!/usr/bin/env python3

import time

from fastapi import HTTPException, Request
from limits import parse
from limits.aio.strategies import MovingWindowRateLimiter
from limits.storage import storage_from_string

from shared import RATE_LIMIT_SETTINGS


def setting(name: str, default: str) -> str:
    return RATE_LIMIT_SETTINGS.get(name, default)


# Counters live in this process unless STORAGE_URI points to a shared store such
# as Redis, which is needed when the app runs with several workers.
limiter = MovingWindowRateLimiter(storage_from_string("async+" + setting("STORAGE_URI", "memory://")))

LOGIN_FAILURES_PER_ACCOUNT = parse(setting("LOGIN_FAILURES_PER_ACCOUNT", "5/15minutes"))
LOGIN_ATTEMPTS_PER_IP = parse(setting("LOGIN_ATTEMPTS_PER_IP", "30/15minutes"))
EMAILS_PER_ADDRESS = parse(setting("EMAILS_PER_ADDRESS", "3/hour"))
EMAIL_REQUESTS_PER_IP = parse(setting("EMAIL_REQUESTS_PER_IP", "10/hour"))
REGISTRATIONS_PER_IP = parse(setting("REGISTRATIONS_PER_IP", "10/hour"))
PASSWORD_CHANGE_FAILURES_PER_ACCOUNT = parse(setting("PASSWORD_CHANGE_FAILURES_PER_ACCOUNT", "5/15minutes"))


def client_ip(request: Request) -> str:
    # The real client behind a trusted proxy: uvicorn fills it in from
    # X-Forwarded-For when the proxy's address is in --forwarded-allow-ips.
    return request.client.host if request.client else "unknown"


def normalize(email: object) -> str:
    return str(email).strip().lower()


async def enforce(request: Request) -> None:
    """Router dependency: applies the limits of the route being called, if any."""
    route = request.scope["route"].name
    ip = client_ip(request)

    if route.startswith("auth:") and route.endswith(".login"):
        email = normalize((await request.form()).get("username", ""))
        checks = [
            (LOGIN_ATTEMPTS_PER_IP, "login-ip", ip),
            (LOGIN_FAILURES_PER_ACCOUNT, "login-failures", ip, email),
        ]
    elif route in ("reset:forgot_password", "verify:request-token"):
        body = await request.json()
        email = normalize(body.get("email", "") if isinstance(body, dict) else "")
        # Counted per address whether it has an account or not, so a 429 says
        # nothing about which emails are registered.
        checks = [
            (EMAIL_REQUESTS_PER_IP, "email-ip", ip),
            (EMAILS_PER_ADDRESS, "email-to", email),
        ]
    elif route == "register:register":
        checks = [(REGISTRATIONS_PER_IP, "register-ip", ip)]
    else:
        return

    for limit, *key in checks:
        await consume(limit, *key)


async def consume(limit, *key: str) -> None:
    """Counts one request against the limit, or answers 429 when it's used up."""
    if not await limiter.hit(limit, *key):
        window = await limiter.get_window_stats(limit, *key)
        retry_after = max(1, int(window.reset_time - time.time()))
        raise HTTPException(429, "TOO_MANY_REQUESTS", headers={"Retry-After": str(retry_after)})


async def login_succeeded(request: Request, email: str) -> None:
    # Only consecutive failures count towards the per-account login limit.
    await limiter.clear(LOGIN_FAILURES_PER_ACCOUNT, "login-failures", client_ip(request), normalize(email))


async def password_change_attempted(user_id: object) -> None:
    # Per account, not per IP: only someone signed in to it gets this far, and
    # switching IPs mustn't buy more guesses at the current password.
    await consume(PASSWORD_CHANGE_FAILURES_PER_ACCOUNT, "password-change-failures", str(user_id))


async def password_change_succeeded(user_id: object) -> None:
    await limiter.clear(PASSWORD_CHANGE_FAILURES_PER_ACCOUNT, "password-change-failures", str(user_id))
