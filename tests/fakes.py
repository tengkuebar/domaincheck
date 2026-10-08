"""Test doubles. Tests never touch the real internet."""

from __future__ import annotations

from collections.abc import Callable

import httpx

from app.checks.base import CheckContext
from app.dns import DnsError
from app.fetcher import SafeFetcher

PUBLIC_IP = "93.184.216.34"


class FakeResolver:
    """Scripted resolver. ``set`` takes one answer per call; the last answer repeats."""

    def __init__(self) -> None:
        self._answers: dict[tuple[str, str], list[list[str] | DnsError]] = {}
        self.calls: list[tuple[str, str]] = []

    def set(self, name: str, rtype: str, *answers: list[str] | DnsError) -> FakeResolver:
        self._answers[(name.lower(), rtype.upper())] = list(answers)
        return self

    def query(self, name: str, rtype: str) -> list[str]:
        key = (name.lower().rstrip("."), rtype.upper())
        self.calls.append(key)
        queue = self._answers.get(key)
        if not queue:
            return []
        answer = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(answer, DnsError):
            raise answer
        return list(answer)


def web_ctx(
    handler: Callable[[httpx.Request], httpx.Response], domain: str = "example.com"
) -> CheckContext:
    """A CheckContext whose fetcher talks to ``handler`` instead of the network.

    The handler sees the original (logical) URL: scheme, host and path.
    """
    resolver = FakeResolver().set(domain, "A", [PUBLIC_IP])

    def transport(request: httpx.Request) -> httpx.Response:
        # The fetcher connects to the pinned IP; rebuild the logical URL for the handler.
        logical = request.url.copy_with(host=request.headers["Host"])
        response = handler(httpx.Request(request.method, logical, headers=request.headers))
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=httpx.ByteStream(response.content),
        )

    fetcher = SafeFetcher(resolver, transport=httpx.MockTransport(transport))
    return CheckContext(domain=domain, resolver=resolver, fetcher=fetcher)
