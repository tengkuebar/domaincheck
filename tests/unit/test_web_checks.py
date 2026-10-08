import httpx
import pytest

from app.checks import caa, cookies, headers, https, paths
from app.checks.base import Status
from app.dns import DnsError
from app.fetcher import FetchError
from tests.fakes import FakeResolver, web_ctx

GOOD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


def site(https_headers=None, http_response=None, status=200, body=b"hi"):
    """Handler: HTTPS returns the given headers; HTTP redirects to HTTPS unless overridden."""

    def handler(request):
        if request.url.scheme == "http":
            return http_response or httpx.Response(
                301, headers={"Location": "https://example.com/"}
            )
        return httpx.Response(status, headers=https_headers or {}, content=body)

    return handler


# ---- headers -------------------------------------------------------------------------------


def test_headers_all_good():
    f = headers.run(web_ctx(site(GOOD_HEADERS)))
    assert f.status is Status.PASS


def test_headers_none_fails():
    f = headers.run(web_ctx(site({})))
    assert f.status is Status.FAIL and "Content-Security-Policy" in f.explanation


def test_headers_some_missing_warns():
    h = dict(GOOD_HEADERS)
    del h["Permissions-Policy"]
    f = headers.run(web_ctx(site(h)))
    assert f.status is Status.WARN and "Missing: Permissions-Policy" in f.explanation


@pytest.mark.parametrize(
    "csp",
    [
        "script-src 'self' 'unsafe-inline'",
        "default-src *",
        "default-src 'self' 'unsafe-eval'",
        "img-src 'self'",
    ],
)
def test_weak_csp(csp):
    h = dict(GOOD_HEADERS, **{"Content-Security-Policy": csp + "; frame-ancestors 'none'"})
    f = headers.run(web_ctx(site(h)))
    assert f.status is Status.WARN and f.evidence["Content-Security-Policy"]["verdict"] == "weak"


def test_xfo_satisfied_by_frame_ancestors_or_header():
    h = dict(GOOD_HEADERS, **{"Content-Security-Policy": "default-src 'self'"})
    assert headers.run(web_ctx(site(h))).evidence["X-Frame-Options"]["verdict"] == "missing"
    h["X-Frame-Options"] = "SAMEORIGIN"
    assert headers.run(web_ctx(site(h))).evidence["X-Frame-Options"]["verdict"] == "ok"
    h["X-Frame-Options"] = "ALLOW-FROM https://x.test"
    assert headers.run(web_ctx(site(h))).evidence["X-Frame-Options"]["verdict"] == "weak"


def test_referrer_unsafe_url_is_weak():
    h = dict(GOOD_HEADERS, **{"Referrer-Policy": "unsafe-url"})
    assert headers.run(web_ctx(site(h))).status is Status.WARN


def test_headers_follow_redirect_to_final_page():
    def handler(request):
        if request.url.host == "example.com":
            return httpx.Response(301, headers={"Location": "https://www.example.com/"})
        return httpx.Response(200, headers=GOOD_HEADERS)

    ctx = web_ctx(handler)
    ctx.resolver.set("www.example.com", "A", ["93.184.216.35"])
    assert headers.run(ctx).status is Status.PASS


def test_unreachable_site_raises_fetch_error():
    def handler(request):
        raise httpx.ConnectError("refused")

    with pytest.raises(FetchError):
        headers.run(web_ctx(handler))


# ---- https / HSTS ---------------------------------------------------------------------------


def test_https_pass():
    assert https.run(web_ctx(site(GOOD_HEADERS))).status is Status.PASS


def test_http_served_without_redirect_fails():
    plain = httpx.Response(200, content=b"plain")
    f = https.run(web_ctx(site(GOOD_HEADERS, http_response=plain)))
    assert f.status is Status.FAIL and "without redirecting" in f.explanation


def test_http_redirecting_to_http_fails():
    r = httpx.Response(301, headers={"Location": "http://example.com/other"})
    assert https.run(web_ctx(site(GOOD_HEADERS, http_response=r))).status is Status.FAIL


def test_relative_redirect_is_resolved():
    r = httpx.Response(301, headers={"Location": "/x"})
    # A relative redirect from http stays on http, which is not good enough.
    assert https.run(web_ctx(site(GOOD_HEADERS, http_response=r))).status is Status.FAIL


def test_missing_hsts_warns():
    h = {k: v for k, v in GOOD_HEADERS.items() if k != "Strict-Transport-Security"}
    f = https.run(web_ctx(site(h)))
    assert f.status is Status.WARN and "HSTS" in f.explanation


@pytest.mark.parametrize("value", ["max-age=0", "max-age=3600"])
def test_weak_hsts_warns(value):
    h = dict(GOOD_HEADERS, **{"Strict-Transport-Security": value})
    assert https.run(web_ctx(site(h))).status is Status.WARN


def test_port_80_closed_is_warn_not_fail():
    def handler(request):
        if request.url.scheme == "http":
            raise httpx.ConnectError("refused")
        return httpx.Response(200, headers=GOOD_HEADERS)

    f = https.run(web_ctx(handler))
    assert f.status is Status.WARN and "not reachable" in f.explanation


def test_parse_hsts():
    assert https.parse_hsts("max-age=63072000; includeSubDomains; preload") == {
        "max_age": 63072000,
        "include_subdomains": True,
        "preload": True,
    }
    assert https.parse_hsts(None) is None


# ---- cookies -------------------------------------------------------------------------------


def cookie_site(*set_cookies):
    def handler(request):
        return httpx.Response(200, headers=[("set-cookie", c) for c in set_cookies])

    return handler


def test_no_cookies_passes():
    assert cookies.run(web_ctx(cookie_site())).status is Status.PASS


def test_good_cookie_passes():
    f = cookies.run(web_ctx(cookie_site("sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/")))
    assert f.status is Status.PASS


def test_missing_secure_fails_and_value_not_recorded():
    f = cookies.run(web_ctx(cookie_site("sid=topsecretvalue; HttpOnly; SameSite=Lax")))
    assert f.status is Status.FAIL and "topsecretvalue" not in str(f.evidence)


def test_missing_httponly_or_samesite_warns():
    assert cookies.run(web_ctx(cookie_site("a=1; Secure; SameSite=Lax"))).status is Status.WARN
    assert cookies.run(web_ctx(cookie_site("a=1; Secure; HttpOnly"))).status is Status.WARN


def test_host_prefix_counts_as_secure():
    f = cookies.run(web_ctx(cookie_site("__Host-sid=1; HttpOnly; SameSite=Strict")))
    assert f.status is Status.PASS


def test_multiple_cookies_worst_wins():
    f = cookies.run(web_ctx(cookie_site("a=1; Secure; HttpOnly; SameSite=Lax", "b=2; HttpOnly")))
    assert f.status is Status.FAIL and "b" in f.explanation


# ---- caa -----------------------------------------------------------------------------------


def test_caa_missing_warns():
    ctx = web_ctx(site())
    assert caa.run(ctx).status is Status.WARN


def test_caa_present_passes():
    ctx = web_ctx(site())
    ctx.resolver.set("example.com", "CAA", ['0 issue "letsencrypt.org"'])
    assert caa.run(ctx).status is Status.PASS


def test_caa_dns_error_propagates():
    ctx = web_ctx(site())
    ctx.resolver.set("example.com", "CAA", DnsError("x"))
    with pytest.raises(DnsError):
        caa.run(ctx)


# ---- sensitive paths -----------------------------------------------------------------------


def path_site(files: dict[str, bytes], catch_all: bytes | None = None):
    def handler(request):
        if request.url.path in files:
            return httpx.Response(200, content=files[request.url.path])
        if catch_all is not None:
            return httpx.Response(200, content=catch_all)
        return httpx.Response(404)

    return handler


def test_nothing_exposed():
    f = paths.run(web_ctx(path_site({})))
    assert f.status is Status.PASS and f.evidence["exposed"] == []


def test_exposed_git_and_env_detected_without_storing_content():
    files = {"/.git/HEAD": b"ref: refs/heads/main\n", "/.env": b"DB_PASSWORD=hunter2hunter2\n"}
    f = paths.run(web_ctx(path_site(files)))
    assert f.status is Status.FAIL and f.evidence["exposed"] == ["/.git/HEAD", "/.env"]
    assert "hunter2" not in str(f.evidence) and "hunter2" not in f.explanation


def test_soft_404_page_is_not_a_false_alarm():
    f = paths.run(web_ctx(path_site({}, catch_all=b"<html>Welcome! Page not found</html>")))
    assert f.status is Status.PASS


def test_redirects_are_not_followed_or_counted():
    def handler(request):
        return httpx.Response(302, headers={"Location": "https://example.com/login"})

    assert paths.run(web_ctx(handler)).status is Status.PASS


def test_path_list_is_fixed_and_each_path_requested_once_over_https():
    seen = []

    def handler(request):
        seen.append((request.url.scheme, request.url.path))
        return httpx.Response(404)

    paths.run(web_ctx(handler))
    assert [p for _, p in seen] == [p for p, _ in paths.PATHS]
    assert {s for s, _ in seen} == {"https"}
    assert "/.git/HEAD" in dict(paths.PATHS) and "/.env" in dict(paths.PATHS)


def test_all_paths_unreachable_raises():
    def handler(request):
        raise httpx.ConnectError("refused")

    with pytest.raises(FetchError):
        paths.run(web_ctx(handler))


def test_fake_resolver_unused_import_guard():
    assert FakeResolver()
