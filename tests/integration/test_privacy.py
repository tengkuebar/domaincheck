"""The privacy page makes claims. Each test checks one of them against what the app really does."""

import re

from app.scanning.store import RESULT_TTL
from app.web.ratelimit import Limiters
from tests.web_helpers import canned_runner, make_client, scan


def visit_everything(client):
    """Landing, privacy, scan, report and PDF: every kind of page a visitor can reach."""
    responses = [client.get("/"), client.get("/privacy")]
    redirect = scan(client, "example.com")
    responses.append(redirect)
    path = redirect.headers["location"]
    responses += [client.get(path), client.get(f"{path}/report.pdf"), client.get("/static/app.js")]
    return responses


def test_privacy_page_and_links():
    client, _ = make_client()
    page = client.get("/privacy")
    assert page.status_code == 200
    for claim in [
        "No account",
        "No database",
        "one hour",
        "dc_session",
        "8 hours",
        "No tracking, advertising or analytics",
        "Anyone who has the link can read the report",
        "request logs",
    ]:
        assert claim in page.text
    for path in ["/", "/privacy"]:
        assert 'href="/privacy"' in client.get(path).text  # footer link on every page


def test_landing_has_the_checklist():
    html = make_client()[0].get("/").text
    assert "Privacy at a glance" in html
    assert html.count('<span class="tick" aria-hidden="true">') == 5
    assert 'class="tick warn"' in html  # the honest limit is listed too


def test_only_one_cookie_is_ever_set_and_it_matches_the_page():
    client, _ = make_client(canned_runner())
    names = set()
    for response in visit_everything(client):
        for header in response.headers.get_list("set-cookie"):
            names.add(header.split("=", 1)[0])
            low = header.lower()
            assert "httponly" in low and "samesite=lax" in low and "secure" in low
            assert f"max-age={8 * 3600}" in low  # "8 hours" on the privacy page
    assert names == {"dc_session"}
    assert set(client.cookies.keys()) == {"dc_session"}


def test_cookie_holds_no_personal_data():
    client, _ = make_client()
    client.get("/")
    value = client.cookies.get("dc_session")
    assert "example" not in value and "@" not in value  # nothing the visitor typed


def test_nothing_is_loaded_from_other_sites():
    client, _ = make_client(canned_runner())
    for response in visit_everything(client)[:2] + visit_everything(client)[3:4]:
        external = re.findall(r'(?:src|href|action)="(https?://[^"]+)"', response.text)
        assert external == [], external


def test_no_browser_storage_or_trackers_in_the_script():
    js = make_client()[0].get("/static/app.js").text
    for name in [
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "document.cookie",
        "XMLHttpRequest",
    ]:
        assert name not in js
    assert js.count("fetch(") == 1  # only the same-site poll while a scan runs


def test_nothing_is_written_to_disk(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    client, _ = make_client(canned_runner())
    visit_everything(client)
    assert list(tmp_path.iterdir()) == []  # no database, no report files, no PDFs


def test_retention_matches_what_the_page_says():
    assert RESULT_TTL == 3600  # "one hour"
    limiters = Limiters()
    for limiter in (limiters.scan_ip, limiters.scan_domain, limiters.scan_global):
        assert limiter.window == 3600  # counters are kept "up to one hour"


def test_privacy_page_matches_the_accessibility_basics():
    html = make_client()[0].get("/privacy").text
    assert html.count("<h1") == 1 and '<html lang="en">' in html
    levels = [int(m) for m in re.findall(r"<h([1-6])\b", html)]
    assert all(b - a <= 1 for a, b in zip(levels, levels[1:], strict=False))
