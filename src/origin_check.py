from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class OriginCheckMiddleware:
    """Rejects state-changing requests that a browser sent from another site.

    The session cookie is SameSite=Lax, which already keeps other sites from
    sending it with a POST. This is a second layer, and it also covers sign-in,
    which needs no cookie. Requests without an Origin header pass: browsers
    always send it with these methods, and API clients don't carry the cookie.
    """

    def __init__(self, app: ASGIApp, public_url: str) -> None:
        self.app = app
        public_url = urlsplit(public_url)
        self.public_origin = f"{public_url.scheme}://{public_url.netloc}"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] in UNSAFE_METHODS:
            headers = Headers(scope=scope)
            origin = headers.get("origin")
            if origin is not None and not self.allowed(origin, headers.get("host")):
                response = JSONResponse({"detail": "CROSS_ORIGIN_REQUEST"}, status_code=403)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)

    def allowed(self, origin: str, host: str | None) -> bool:
        # The configured public origin, or the host the browser is talking to
        # (e.g. localhost in development).
        return origin == self.public_origin or (host is not None and urlsplit(origin).netloc == host)
