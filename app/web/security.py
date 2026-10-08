"""Signed-cookie CSRF token. The cookie holds only a random token, never user data (SR-06)."""

from __future__ import annotations

import hmac
import secrets

from itsdangerous import BadSignature, URLSafeTimedSerializer


class Session:
    """Carries the CSRF token. ``dirty`` tells the middleware to send a fresh cookie."""

    def __init__(self, csrf: str | None = None) -> None:
        self.dirty = csrf is None
        self.csrf = csrf or secrets.token_urlsafe(32)

    def csrf_ok(self, submitted: str) -> bool:
        return bool(submitted) and hmac.compare_digest(submitted, self.csrf)


class SessionCodec:
    def __init__(self, secret_key: str, max_age: int) -> None:
        self._serializer = URLSafeTimedSerializer(secret_key, salt="domaincheck-csrf")
        self.max_age = max_age

    def dumps(self, session: Session) -> str:
        return self._serializer.dumps({"csrf": session.csrf})

    def loads(self, cookie: str | None) -> Session:
        if cookie:
            try:
                data = self._serializer.loads(cookie, max_age=self.max_age)
            except BadSignature:
                return Session()
            if isinstance(data, dict) and isinstance(data.get("csrf"), str):
                return Session(data["csrf"])
        return Session()
