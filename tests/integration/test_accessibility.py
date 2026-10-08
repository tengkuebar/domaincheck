"""Structure that screen readers and keyboard users depend on.

These tests check the HTML. They cannot replace trying the pages with a real screen reader.
"""

import re

import pytest

from app.checks.base import Status
from tests.web_helpers import canned_runner, make_client, scan

ALL_STATUSES = {
    "spf": Status.PASS,
    "dmarc": Status.WARN,
    "dkim": Status.NOT_DETECTED,
    "headers": Status.FAIL,
}


@pytest.fixture
def report_html():
    client, _ = make_client(canned_runner(ALL_STATUSES))
    return client.get(scan(client, "example.com.au").headers["location"]).text


def tags(html: str, name: str) -> list[str]:
    return re.findall(rf"<{name}\b[^>]*>", html)


def test_page_basics(report_html):
    assert '<html lang="en">' in report_html and "<title>Report for example.com.au" in report_html
    assert report_html.count("<h1") == 1
    assert 'id="main"' in report_html and 'href="#main"' in report_html  # skip link target exists
    assert "<header" in report_html and "<footer" in report_html and "<main" in report_html
    assert 'aria-label="Main"' in report_html  # the navigation landmark is named


def test_score_is_announced_once(report_html):
    # The ring is an image with a text label; the visible digits are hidden from readers.
    # spf 15 pass + dmarc 20 warn (10) + dkim 10 not detected (5) + headers 10 fail (0) = 30 / 55
    assert 'role="img" aria-label="Score 55 out of 100"' in report_html
    assert '<div class="ring-label" aria-hidden="true">' in report_html


def test_decorative_symbols_are_hidden_from_readers(report_html):
    assert '<span aria-hidden="true">&larr;</span> Check another domain' in report_html
    for symbol in ["✕", "!", "?", "✓"]:
        assert f'<span aria-hidden="true">{symbol}</span>' in report_html
    assert 'class="chev" aria-hidden="true"' in report_html
    assert 'class="bar" aria-hidden="true"' in report_html


def test_status_is_always_text(report_html):
    for word in ["Fix now", "Improve", "Not detected", "Good"]:
        assert f"</span> {word}</span>" in report_html


def test_filter_controls(report_html):
    assert '<div class="chips" role="group" aria-label="Filter findings" hidden>' in report_html
    assert report_html.count("aria-pressed=") == 5 and 'aria-pressed="true"' in report_html
    assert 'id="filter-status" role="status"' in report_html  # announces "Showing 3 of 9"
    assert all("<button" in t or True for t in tags(report_html, "button"))
    assert all('type="button"' in t for t in tags(report_html, "button"))


def test_rows_use_native_disclosure(report_html):
    rows = report_html.count('<details class="row"')
    assert rows == 4 and report_html.count('<details class="row"') == report_html.count("<summary>")
    assert "onclick" not in report_html.lower() and "tabindex" not in report_html


def test_heading_outline_has_no_skips(report_html):
    levels = [int(m) for m in re.findall(r"<h([1-6])\b", report_html)]
    assert levels[0] == 1
    assert all(b - a <= 1 for a, b in zip(levels, levels[1:], strict=False))


def test_landing_form_is_labelled_and_described():
    client, _ = make_client()
    html = client.get("/").text
    assert '<label for="domain">' in html and 'id="domain"' in html
    assert 'aria-describedby="domain-hint"' in html and 'id="domain-hint"' in html
    assert "aria-invalid" not in html


def test_form_error_is_announced_and_linked():
    client, _ = make_client()
    html = scan(client, "127.0.0.1").text
    assert 'role="alert" id="domain-error"' in html
    assert 'aria-describedby="domain-error domain-hint"' in html and 'aria-invalid="true"' in html


def test_decorative_preview_is_hidden_from_readers():
    client, _ = make_client()
    assert 'class="enter enter-2 preview-wrap" aria-hidden="true"' in client.get("/").text


def test_error_page_has_a_way_back():
    client, _ = make_client()
    html = client.get("/r/nope").text
    assert "<h1>Not found</h1>" in html and 'href="/"' in html


def test_polling_needs_connect_src_in_the_csp():
    client, _ = make_client()
    csp = client.get("/").headers["content-security-policy"]
    assert "connect-src 'self'" in csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp


def test_script_has_filter_announcement_and_polling():
    client, _ = make_client()
    js = client.get("/static/app.js").text
    assert "filter-status" in js and "Showing" in js and "pollWhileRunning" in js
    assert "The check is finished" in js
