"""tls_probe must apply the same address rules as fetch (SR-01, SR-03)."""

import pytest

from app.fetcher import BlockedTargetError, FetchError, SafeFetcher, TlsResult
from app.fetcher.tls import TlsConnectError
from tests.fakes import PUBLIC_IP, FakeResolver


def fetcher(resolver, calls=None, raises=None):
    def handshake(ip, host, **kw):
        if calls is not None:
            calls.append((ip, host, kw))
        if raises:
            raise raises
        return TlsResult(ok=True)

    return SafeFetcher(resolver, handshake=handshake)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1"])
def test_internal_addresses_refused_before_any_connection(ip):
    calls = []
    rtype = "AAAA" if ":" in ip else "A"
    f = fetcher(FakeResolver().set("evil.test", rtype, [ip]), calls)
    with pytest.raises(BlockedTargetError):
        f.tls_probe("evil.test")
    assert calls == []


def test_ip_literal_refused():
    calls = []
    with pytest.raises(BlockedTargetError):
        fetcher(FakeResolver(), calls).tls_probe("8.8.8.8")
    assert calls == []


def test_connects_to_validated_ip_with_hostname_for_sni():
    calls = []
    fetcher(FakeResolver().set("ok.test", "A", [PUBLIC_IP]), calls).tls_probe("OK.test.")
    ip, host, kw = calls[0]
    assert ip == PUBLIC_IP and host == "ok.test" and kw["verify"] is True


def test_rebinding_resolves_once_per_probe():
    r = FakeResolver().set("rebind.test", "A", [PUBLIC_IP], ["10.0.0.1"])
    calls = []
    f = fetcher(r, calls)
    f.tls_probe("rebind.test")
    assert calls[0][0] == PUBLIC_IP and r.calls.count(("rebind.test", "A")) == 1
    with pytest.raises(BlockedTargetError):  # the next probe re-validates and sees the new answer
        f.tls_probe("rebind.test")


def test_connection_errors_become_fetch_errors():
    f = fetcher(FakeResolver().set("ok.test", "A", [PUBLIC_IP]), raises=TlsConnectError("x"))
    with pytest.raises(FetchError):
        f.tls_probe("ok.test")
