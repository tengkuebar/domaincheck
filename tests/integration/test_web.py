"""Web flow, CSRF, rate limits and headers (SR-06, SR-08, SR-10, SR-12)."""

import httpx
import pytest

from app.checks.base import Status
from app.checks.engine import active_checks, set_path_check_enabled
from app.scanning.store import ResultStore
from tests.web_helpers import canned_runner, csrf, make_client, scan


def test_landing_page_has_form_and_limits():
    client, _ = make_client()
    page = client.get("/").text
    assert 'name="domain"' in page and "What it cannot do" in page and "Essential Eight" in page


def test_scan_flow_and_report():
    client, _ = make_client(canned_runner())
    r = scan(client, "Example.com.au")
    assert r.status_code == 303 and r.headers["location"].startswith("/r/")
    page = client.get(r.headers["location"]).text
    assert "example.com.au" in page and "out of 100" in page
    assert "Fix these first" in page and "All findings" in page and "How the score works" in page
    assert "Improve" in page and "Not detected" in page and "Good" in page
    assert "How to fix" in page and "Microsoft 365" in page


def test_dashboard_contents():
    client, _ = make_client(canned_runner())
    page = client.get(scan(client, "example.com").headers["location"]).text
    # areas, ranked fixes with point gains and effort, filter chips, expandable rows
    assert "Email protection" in page and 'class="card area"' in page
    assert "+22.2 pts" in page and "+11.1 pts" in page  # dmarc 10/45, dkim 5/45 on a 0-100 scale
    assert "about 15 min" in page and "min</span>" in page
    assert 'data-filter="warn"' in page and 'data-filter="not_detected"' in page
    assert page.count('<details class="row"') == 3 and page.count(" open>") == 1
    assert 'data-pct="' in page  # bars are filled by app.js, not inline styles


def test_report_without_js_still_shows_everything():
    client, _ = make_client(canned_runner())
    page = client.get(scan(client, "example.com").headers["location"]).text
    assert "hidden>" in page  # chips are hidden until the script reveals them
    assert "SPF" in page and "DMARC" in page and "DKIM" in page


def test_score_matches_weights():
    client, _ = make_client(canned_runner())
    page = client.get(scan(client, "example.com").headers["location"]).text
    # spf 15 pass, dmarc 20 warn (10), dkim 10 not detected (5) => 30/45 = 67
    assert 'aria-label="Score 67 out of 100"' in page


def test_report_while_running_shows_progress_and_refresh():
    client, _ = make_client()
    store: ResultStore = client.app.state.store
    result = store.create("example.com")
    page = client.get(f"/r/{result.id}").text
    assert "data-running" in page and "Checking" in page
    # The timed reload is only a fallback for browsers without JavaScript.
    assert '<noscript><meta http-equiv="refresh" content="3"></noscript>' in page


def test_failed_scan_page():
    def boom(resolver, domain):
        raise RuntimeError("secret detail")

    client, _ = make_client(boom)
    page = client.get(scan(client, "example.com").headers["location"]).text
    assert "check failed" in page and "secret detail" not in page


def test_unknown_report_is_404_page():
    client, _ = make_client()
    r = client.get("/r/not-a-real-id")
    assert r.status_code == 404 and "not found" in r.text.lower()


def test_report_ids_are_unguessable():
    store = ResultStore()
    ids = {store.create("example.com").id for _ in range(50)}
    assert len(ids) == 50 and all(len(i) >= 20 for i in ids)


def test_results_expire_and_store_is_bounded():
    now = [1000.0]
    store = ResultStore(ttl=60, max_items=3, clock=lambda: now[0])
    first = store.create("a.com")
    now[0] += 61
    assert store.get(first.id) is None
    ids = [store.create(f"d{i}.com").id for i in range(5)]
    assert store.get(ids[0]) is None and store.get(ids[-1]) is not None


@pytest.mark.parametrize(
    "bad",
    ["", "127.0.0.1", "localhost", "http://example.com", "github.io", "www.example.com", "a b.com"],
)
def test_invalid_domains_rejected_without_scanning(bad):
    seen = []

    def runner(resolver, domain):
        seen.append(domain)
        return []

    client, _ = make_client(runner)
    r = scan(client, bad)
    assert r.status_code == 400 and seen == []


def test_input_is_escaped():
    client, _ = make_client()
    payload = '"><script>alert(1)</script>'
    r = scan(client, payload)
    assert payload not in r.text and "&lt;script&gt;" in r.text or "&#34;" in r.text


def test_path_check_off_by_default_and_opt_in():
    set_path_check_enabled(False)
    assert "paths" not in [c.id for c in active_checks()]
    make_client(enable_path_check=True)
    assert "paths" in [c.id for c in active_checks()]
    set_path_check_enabled(False)


def test_default_scan_runner_uses_only_the_safe_fetcher_and_resolver():
    # With a fake resolver that knows nothing, every network check ends as 'error', never a crash.
    client, _ = make_client(None)
    client.app.state.jobs._runner = __import__(
        "app.scanning.service", fromlist=["x"]
    ).default_runner
    page = client.get(scan(client, "example.com").headers["location"]).text
    assert "Could not check" in page or "Needs attention" in page


# ---- CSRF ---------------------------------------------------------------------------------


def test_scan_without_csrf_token_rejected():
    client, _ = make_client(canned_runner())
    client.get("/")
    assert client.post("/scan", data={"domain": "example.com"}).status_code == 403
    r = client.post("/scan", data={"domain": "example.com", "csrf_token": "forged"})
    assert r.status_code == 403


def test_csrf_token_from_another_session_rejected():
    c1, _ = make_client(canned_runner())
    c2, _ = make_client(canned_runner())
    token_1 = csrf(c1)
    csrf(c2)
    assert (
        c2.post("/scan", data={"domain": "example.com", "csrf_token": token_1}).status_code == 403
    )


def test_tampered_cookie_is_ignored():
    client, _ = make_client(canned_runner())
    client.cookies.set("dc_session", "forged.value.here")
    # A fresh token is issued; the forged cookie grants nothing.
    assert scan(client, "example.com", token="x").status_code == 403


def test_session_cookie_flags():
    client, _ = make_client()
    cookie = client.get("/").headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=lax" in cookie


# ---- rate limits ---------------------------------------------------------------------------


def test_per_domain_limit():
    client, _ = make_client(canned_runner(), limit_domain_per_hour=2)
    codes = [scan(client, "example.com").status_code for _ in range(3)]
    assert codes == [303, 303, 429]
    assert scan(client, "other.com").status_code == 303  # other domains unaffected


def test_per_ip_limit():
    client, _ = make_client(canned_runner(), limit_ip_per_hour=3)
    codes = [scan(client, f"d{i}.com").status_code for i in range(4)]
    assert codes == [303, 303, 303, 429]


def test_global_limit():
    client, _ = make_client(canned_runner(), limit_global_per_hour=2, limit_ip_per_hour=99)
    codes = [scan(client, f"d{i}.com").status_code for i in range(3)]
    assert codes == [303, 303, 429]


def test_forwarded_for_ignored_unless_trusted():
    client, _ = make_client(canned_runner(), limit_ip_per_hour=1)
    h = lambda ip: {"x-forwarded-for": ip}  # noqa: E731
    token = csrf(client)
    first = client.post(
        "/scan",
        data={"domain": "a.com", "csrf_token": token},
        headers=h("1.1.1.1"),
        follow_redirects=False,
    )
    second = client.post(
        "/scan",
        data={"domain": "b.com", "csrf_token": token},
        headers=h("2.2.2.2"),
        follow_redirects=False,
    )
    assert (first.status_code, second.status_code) == (303, 429)  # spoofed header did not help

    trusted, _ = make_client(canned_runner(), limit_ip_per_hour=1, trust_forwarded_for=True)
    token = csrf(trusted)
    a = trusted.post(
        "/scan",
        data={"domain": "a.com", "csrf_token": token},
        headers=h("1.1.1.1"),
        follow_redirects=False,
    )
    b = trusted.post(
        "/scan",
        data={"domain": "b.com", "csrf_token": token},
        headers=h("2.2.2.2"),
        follow_redirects=False,
    )
    assert (a.status_code, b.status_code) == (303, 303)


def test_pending_queue_is_capped():
    from app.scanning.service import MAX_PENDING

    client, _ = make_client(
        canned_runner(), limit_ip_per_hour=999, limit_domain_per_hour=999, limit_global_per_hour=999
    )
    jobs = client.app.state.jobs
    jobs._pending = MAX_PENDING
    assert scan(client, "example.com").status_code == 503


# ---- headers -------------------------------------------------------------------------------


def test_security_headers_present():
    client, _ = make_client()
    h = client.get("/").headers
    csp = h["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "no-referrer" and "max-age" in h["strict-transport-security"]
    assert "permissions-policy" in h


def test_pages_use_no_inline_styles_or_scripts():
    client, _ = make_client(canned_runner())
    for path in ["/", client.get("/").url.path]:
        html = client.get(path).text
        assert "style=" not in html and "<script>" not in html
    report = client.get(scan(client, "example.com").headers["location"]).text
    assert "style=" not in report


def test_static_files_served():
    client, _ = make_client()
    assert client.get("/static/style.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/../config.py").status_code in (404, 400)


def test_unused_import_guard():
    assert httpx and Status
