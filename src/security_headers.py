#!/usr/bin/env python3

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send


# For the app's pages: only its own files (no inline scripts or styles, and no
# eval, thanks to Alpine's CSP build), nothing from other sites, no framing.
CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
])

# FastAPI's API docs load Swagger UI and ReDoc from a CDN, with inline scripts.
DOCS_PATHS = ("/docs", "/redoc")


class SecurityHeadersMiddleware:
    """Adds security headers to every response, and the CSP to HTML pages."""

    def __init__(self, app: ASGIApp, https: bool) -> None:
        self.app = app
        self.headers = {
            "X-Content-Type-Options": "nosniff",
            # The CSP's frame-ancestors, for browsers that predate it (clickjacking).
            "X-Frame-Options": "DENY",
            # Other sites don't see the app's URLs. Not no-referrer: with it, browsers send
            # Origin: null with the app's own form posts, and the Origin check rejects them.
            "Referrer-Policy": "same-origin",
        }
        if https:
            # Browsers stop using plain http for this host for a year.
            self.headers["Strict-Transport-Security"] = "max-age=31536000"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # The path without ROOT_PATH, whether a proxy stripped it or not.
        path, root_path = scope["path"], scope.get("root_path", "")
        if root_path and path.startswith(root_path):
            path = path[len(root_path):]
        is_docs = path.startswith(DOCS_PATHS)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in self.headers.items():
                    headers.setdefault(name, value)
                if not is_docs and headers.get("content-type", "").startswith("text/html"):
                    headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
            await send(message)

        await self.app(scope, receive, send_with_headers)
