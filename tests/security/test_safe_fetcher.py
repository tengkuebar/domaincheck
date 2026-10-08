"""SSRF, rebinding, redirect, size and timeout tests for the safe fetcher (SR-01 to SR-04)."""

import httpx
import pytest

from app.fetcher import BlockedTargetError, FetchError, SafeFetcher
from tests.fakes import FakeResolver

PUBLIC = "93.184.216.34"


def make(resolver, handler=None, **kw):
    seen: list[httpx.Request] = []

    def wrapped(request):
        seen.append(request)
        response = handler(request) if handler else httpx.Response(200, content=b"ok")
        # MockTransport responses are pre-read; re-wrap as a stream like a real transport.
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=httpx.ByteStream(response.content),
        )

    return SafeFetcher(resolver, transport=httpx.MockTransport(wrapped), **kw), seen


@pytest.mark.parametrize(
    "ip", ["127.0.0.1", "10.1.2.3", "192.168.0.5", "169.254.169.254", "::1", "::ffff:127.0.0.1"]
)
def test_refuses_domain_resolving_to_internal(ip):
    rtype = "AAAA" if ":" in ip else "A"
    fetcher, seen = make(FakeResolver().set("evil.test", rtype, [ip]))
    with pytest.raises(BlockedTargetError):
        fetcher.fetch("https://evil.test/")
    assert seen == []


def test_refuses_if_any_address_is_internal():
    r = FakeResolver().set("mixed.test", "A", [PUBLIC, "10.0.0.1"])
    fetcher, seen = make(r)
    with pytest.raises(BlockedTargetError):
        fetcher.fetch("https://mixed.test/")
    assert seen == []


@pytest.mark.parametrize(
    "url",
    [
        "ftp://a.test/", "file:///etc/passwd", "http://127.0.0.1/", "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/", "https://a.test:8443/", "http://a.test:22/",
        "https://user:pw@a.test/", "http:///nohost",
    ],
)  # fmt: skip
def test_refuses_bad_urls(url):
    fetcher, seen = make(FakeResolver().set("a.test", "A", [PUBLIC]))
    with pytest.raises(BlockedTargetError):
        fetcher.fetch(url)
    assert seen == []


def test_asks_for_uncompressed_bodies():
    fetcher, seen = make(FakeResolver().set("a.test", "A", [PUBLIC]))
    fetcher.fetch("https://a.test/")
    assert seen[0].headers["Accept-Encoding"] == "identity"


@pytest.mark.parametrize(
    "location", ["http://2130706433/", "http://0x7f.1/", "http://017700000001/", "http://127.1/"]
)
def test_numeric_host_tricks_in_redirects_are_not_followed(location):
    # Not valid DNS names that resolve anywhere, so they fail as 'does not resolve'.
    def handler(request):
        return httpx.Response(302, headers={"Location": location})

    fetcher, seen = make(FakeResolver().set("pub.test", "A", [PUBLIC]), handler)
    with pytest.raises(FetchError):
        fetcher.fetch("https://pub.test/")
    assert len(seen) == 1


def test_userinfo_trick_in_redirect_is_refused():
    def handler(request):
        return httpx.Response(302, headers={"Location": "http://pub.test@internal.test/"})

    fetcher, seen = make(FakeResolver().set("pub.test", "A", [PUBLIC]), handler)
    with pytest.raises(BlockedTargetError):
        fetcher.fetch("https://pub.test/")
    assert len(seen) == 1


def test_relative_redirect_stays_on_the_validated_host():
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/next?x=1"})
        return httpx.Response(200, content=b"ok")

    fetcher, seen = make(FakeResolver().set("a.test", "A", [PUBLIC]), handler)
    result = fetcher.fetch("https://a.test/start")
    assert result.url == "https://a.test/next?x=1"
    assert {r.url.host for r in seen} == {PUBLIC} and {r.headers["Host"] for r in seen} == {
        "a.test"
    }


def test_connects_to_validated_ip_with_original_host():
    fetcher, seen = make(FakeResolver().set("example.test", "A", [PUBLIC]))
    result = fetcher.fetch("https://example.test/path?q=1")
    req = seen[0]
    assert req.url.host == PUBLIC
    assert req.headers["Host"] == "example.test"
    assert req.extensions["sni_hostname"] == "example.test"
    assert result.ip == PUBLIC and result.body == b"ok"


def test_public_host_redirecting_to_internal_is_refused():
    r = FakeResolver().set("pub.test", "A", [PUBLIC]).set("int.test", "A", ["127.0.0.1"])

    def handler(request):
        return httpx.Response(302, headers={"Location": "https://int.test/admin"})

    fetcher, seen = make(r, handler)
    with pytest.raises(BlockedTargetError):
        fetcher.fetch("https://pub.test/")
    assert len(seen) == 1


@pytest.mark.parametrize(
    "location",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "ftp://pub.test/",
        "https://pub.test:8443/",
    ],
)
def test_redirect_to_bad_url_is_refused(location):
    def handler(request):
        return httpx.Response(302, headers={"Location": location})

    fetcher, seen = make(FakeResolver().set("pub.test", "A", [PUBLIC]), handler)
    with pytest.raises(BlockedTargetError):
        fetcher.fetch("https://pub.test/")
    assert len(seen) == 1


def test_rebinding_between_hops_is_caught_and_single_hop_pins():
    # First lookup public, second lookup private.
    r = FakeResolver().set("rebind.test", "A", [PUBLIC], ["10.0.0.1"])

    # Single hop: exactly one resolution, connection goes to the validated public IP.
    fetcher, seen = make(r)
    fetcher.fetch("https://rebind.test/")
    assert r.calls.count(("rebind.test", "A")) == 1
    assert seen[0].url.host == PUBLIC

    # Redirect to the same name re-resolves, sees the private address and refuses.
    r2 = FakeResolver().set("rebind.test", "A", [PUBLIC], ["10.0.0.1"])

    def handler(request):
        return httpx.Response(302, headers={"Location": "https://rebind.test/again"})

    fetcher2, seen2 = make(r2, handler)
    with pytest.raises(BlockedTargetError):
        fetcher2.fetch("https://rebind.test/")
    assert len(seen2) == 1


def test_follows_safe_redirects_and_records_chain():
    r = FakeResolver().set("a.test", "A", [PUBLIC]).set("b.test", "A", ["8.8.8.8"])

    def handler(request):
        if request.headers["Host"] == "a.test":
            return httpx.Response(301, headers={"Location": "https://b.test/x"})
        return httpx.Response(200, content=b"done")

    fetcher, _ = make(r, handler)
    result = fetcher.fetch("http://a.test/")
    assert result.url == "https://b.test/x" and result.redirects == ["http://a.test/"]


def test_max_redirects_zero_returns_redirect_response():
    def handler(request):
        return httpx.Response(301, headers={"Location": "https://a.test/"})

    fetcher, _ = make(FakeResolver().set("a.test", "A", [PUBLIC]), handler)
    assert fetcher.fetch("http://a.test/", max_redirects=0).status == 301


def test_redirect_loop_is_limited():
    def handler(request):
        return httpx.Response(302, headers={"Location": "https://a.test/"})

    fetcher, seen = make(FakeResolver().set("a.test", "A", [PUBLIC]), handler)
    with pytest.raises(FetchError, match="Too many redirects"):
        fetcher.fetch("https://a.test/")
    assert len(seen) == 6


def test_oversized_body_is_cut_off():
    def handler(request):
        return httpx.Response(200, content=b"x" * 5000)

    fetcher, _ = make(FakeResolver().set("a.test", "A", [PUBLIC]), handler, max_body=1000)
    result = fetcher.fetch("https://a.test/")
    assert len(result.body) == 1000 and result.truncated


def test_timeout_becomes_fetch_error():
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    fetcher, _ = make(FakeResolver().set("a.test", "A", [PUBLIC]), handler)
    with pytest.raises(FetchError, match="timed out"):
        fetcher.fetch("https://a.test/")


def test_total_time_budget_is_enforced():
    fetcher, _ = make(FakeResolver().set("a.test", "A", [PUBLIC]), total_budget=-1)
    with pytest.raises(FetchError, match="time budget"):
        fetcher.fetch("https://a.test/")


def test_unresolvable_domain():
    fetcher, _ = make(FakeResolver())
    with pytest.raises(FetchError, match="does not resolve"):
        fetcher.fetch("https://nowhere.test/")
