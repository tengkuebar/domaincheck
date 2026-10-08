"""Session cookie handling and security response headers (SR-05, SR-10)."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.web.security import SessionCodec

COOKIE_NAME = "dc_session"

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
    "form-action 'self'; "
    "base-uri 'none'; frame-ancestors 'none'"
)


class SessionAndHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, codec: SessionCodec, *, secure_cookies: bool, hsts: bool) -> None:
        super().__init__(app)
        self.codec = codec
        self.secure_cookies = secure_cookies
        self.hsts = hsts

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        session = self.codec.loads(request.cookies.get(COOKIE_NAME))
        request.state.session = session
        response = await call_next(request)
        if session.dirty:
            response.set_cookie(
                COOKIE_NAME,
                self.codec.dumps(session),
                max_age=self.codec.max_age,
                httponly=True,
                secure=self.secure_cookies,
                samesite="lax",
                path="/",
            )
        h = response.headers
        h["Content-Security-Policy"] = CSP
        h["X-Frame-Options"] = "DENY"
        h["X-Content-Type-Options"] = "nosniff"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        h["Cache-Control"] = "no-store"
        if self.hsts:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
