"""The only module that makes HTTP connections (SR-01 to SR-04).

Flow per hop: parse -> resolve -> reject if any address is blocked -> connect to the validated IP
(sending the original hostname for Host and TLS SNI/verification) -> capped read. Redirects
repeat the whole flow, so a redirect to an internal address is refused.
"""

from __future__ import annotations

import ipaddress
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache
from urllib.parse import urljoin, urlsplit

import httpx

from app.dns import DnsError, Resolver, resolve_ips
from app.fetcher.ranges import is_blocked_ip
from app.fetcher.tls import TlsConnectError, TlsResult, real_handshake

REQUEST_TIMEOUT = 5.0  # NFR-02, per request phase
MAX_BODY_BYTES = 1_000_000  # NFR-03
MAX_REDIRECTS = 5
TOTAL_BUDGET = 15.0  # wall-clock cap for one fetch including redirects
ALLOWED_PORTS = {"http": 80, "https": 443}
USER_AGENT = "DomainCheck/0.1 (passive security check)"


@cache
def _ssl_context() -> ssl.SSLContext:
    # Loading the CA bundle is slow, so build the verifying context once per process.
    return httpx.create_ssl_context()


class FetchError(Exception):
    """The fetch was refused or failed. The message is safe to show to the user."""


class BlockedTargetError(FetchError):
    """The target resolved to, or redirected to, a forbidden address or URL."""


@dataclass
class FetchResult:
    url: str
    status: int
    headers: httpx.Headers
    body: bytes
    truncated: bool
    ip: str
    redirects: list[str] = field(default_factory=list)


def _parse(url: str) -> tuple[str, str, str]:
    """Return (scheme, hostname, path_with_query). Raises BlockedTargetError."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_PORTS:
        raise BlockedTargetError("Only http and https URLs are allowed.")
    if parts.username is not None or parts.password is not None:
        raise BlockedTargetError("URLs with credentials are not allowed.")
    try:
        port = parts.port
    except ValueError as exc:
        raise BlockedTargetError("Invalid port.") from exc
    if port is not None and port != ALLOWED_PORTS[scheme]:
        raise BlockedTargetError("Only the default ports 80 and 443 are allowed.")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise BlockedTargetError("URL has no hostname.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise BlockedTargetError("IP addresses are not allowed as targets.")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return scheme, host, path


class SafeFetcher:
    def __init__(
        self,
        resolver: Resolver,
        *,
        transport: httpx.BaseTransport | None = None,
        max_body: int = MAX_BODY_BYTES,
        timeout: float = REQUEST_TIMEOUT,
        total_budget: float = TOTAL_BUDGET,
        handshake: Callable[..., TlsResult] = real_handshake,
    ) -> None:
        self._resolver = resolver
        self._handshake = handshake
        self._transport = transport
        self._max_body = max_body
        self._timeout = timeout
        self._total_budget = total_budget

    def _validated_ip(self, host: str) -> str:
        try:
            addresses = resolve_ips(self._resolver, host)
        except DnsError as exc:
            raise FetchError("DNS lookup failed.") from exc
        if not addresses:
            raise FetchError("Domain does not resolve.")
        if any(is_blocked_ip(a) for a in addresses):
            raise BlockedTargetError("Domain resolves to a blocked address.")
        return addresses[0]

    def tls_probe(
        self,
        host: str,
        *,
        verify: bool = True,
        min_version: ssl.TLSVersion | None = None,
        max_version: ssl.TLSVersion | None = None,
    ) -> TlsResult:
        """One TLS handshake to port 443 of ``host``, on the same validated IP rules as fetch."""
        host = host.strip().rstrip(".").lower()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise BlockedTargetError("IP addresses are not allowed as targets.")
        ip = self._validated_ip(host)
        try:
            return self._handshake(
                ip,
                host,
                verify=verify,
                min_version=min_version,
                max_version=max_version,
                timeout=self._timeout,
            )
        except TlsConnectError as exc:
            raise FetchError("Could not connect over TLS.") from exc

    def fetch(
        self, url: str, *, method: str = "GET", max_redirects: int = MAX_REDIRECTS
    ) -> FetchResult:
        """Fetch ``url``. ``max_redirects=0`` returns a redirect response instead of following."""
        deadline = time.monotonic() + self._total_budget
        chain: list[str] = []
        current = url
        with httpx.Client(
            transport=self._transport,
            timeout=httpx.Timeout(self._timeout),
            follow_redirects=False,
            trust_env=False,
            verify=_ssl_context() if self._transport is None else True,
        ) as client:
            while True:
                scheme, host, path = _parse(current)
                ip = self._validated_ip(host)
                connect_host = f"[{ip}]" if ":" in ip else ip
                target = f"{scheme}://{connect_host}{path}"
                try:
                    with client.stream(
                        method,
                        target,
                        headers={
                            "Host": host,
                            "User-Agent": USER_AGENT,
                            # Bodies are read as raw wire bytes (no decompression, so the size cap
                            # cannot be bypassed), so ask for plain text.
                            "Accept-Encoding": "identity",
                        },
                        extensions={"sni_hostname": host},
                    ) as response:
                        body, truncated = self._read_capped(response, deadline)
                        status, headers = response.status_code, response.headers
                except httpx.TimeoutException as exc:
                    raise FetchError("Request timed out.") from exc
                except httpx.HTTPError as exc:
                    raise FetchError(f"Request failed: {type(exc).__name__}.") from exc

                location = headers.get("location")
                if status in (301, 302, 303, 307, 308) and location and max_redirects > 0:
                    if len(chain) >= max_redirects:
                        raise FetchError("Too many redirects.")
                    chain.append(current)
                    current = urljoin(current, location)
                    continue
                return FetchResult(
                    url=current,
                    status=status,
                    headers=headers,
                    body=body,
                    truncated=truncated,
                    ip=ip,
                    redirects=chain,
                )

    def _read_capped(self, response: httpx.Response, deadline: float) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_raw():
            if time.monotonic() > deadline:
                raise FetchError("Request exceeded the time budget.")
            size += len(chunk)
            if size > self._max_body:
                keep = len(chunk) - (size - self._max_body)
                chunks.append(chunk[:keep])
                return b"".join(chunks), True
            chunks.append(chunk)
        return b"".join(chunks), False
