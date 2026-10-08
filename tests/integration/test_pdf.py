"""PDF export of a finished report."""

import io

from pypdf import PdfReader

from app.checks.base import Finding, Status
from app.web.pdf import clean
from tests.web_helpers import canned_runner, make_client, scan


def pdf_text(content: bytes) -> str:
    return "\n".join(page.extract_text() for page in PdfReader(io.BytesIO(content)).pages)


def report_path(client, domain="example.com.au"):
    return scan(client, domain).headers["location"]


def test_pdf_download_has_the_report_content():
    client, _ = make_client(canned_runner())
    path = report_path(client)
    r = client.get(f"{path}/report.pdf")
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert (
        r.headers["content-disposition"] == 'attachment; filename="domaincheck-example.com.au.pdf"'
    )
    assert r.headers["cache-control"] == "no-store"
    assert r.content.startswith(b"%PDF")
    text = pdf_text(r.content)
    assert "example.com.au" in text and "67" in text and "out of 100" in text
    for heading in ["Fix these first", "All findings", "How the score works", "Areas"]:
        assert heading in text
    assert "IMPROVE" in text and "NOT DETECTED" in text and "GOOD" in text
    assert "HOW TO FIX" in text and "Microsoft 365" in text
    assert "Weights:" in text and "DMARC 20" in text


def test_pdf_matches_the_page_numbers():
    client, _ = make_client(canned_runner())
    path = report_path(client)
    page = client.get(path).text
    text = pdf_text(client.get(f"{path}/report.pdf").content)
    assert "Score 67 out of 100" in page and "67" in text
    assert "+22.2" in text and "+11.1" in text  # same point gains as the dashboard


def test_report_page_links_to_the_pdf():
    client, _ = make_client(canned_runner())
    path = report_path(client)
    assert f'href="{path}/report.pdf"' in client.get(path).text


def test_pdf_not_available_while_running_or_for_unknown_ids():
    client, _ = make_client()
    running = client.app.state.store.create("example.com")
    assert client.get(f"/r/{running.id}/report.pdf").status_code == 404
    assert client.get("/r/not-a-real-id/report.pdf").status_code == 404


def test_hostile_and_unusual_text_does_not_break_the_pdf():
    def runner(resolver, domain):
        return [
            Finding(
                "spf",
                Status.FAIL,
                "SPF <b>bold</b> & more",
                "Explanation with <script>alert(1)</script> & 日本語 😀",
                {
                    "record": "v=spf1 <i>x</i> & -all",
                    "nested": {"a": [1, 2, {"b": None}]},
                    "none": None,
                    "long": "x" * 5000,
                },
            ),
            Finding("dmarc", Status.PASS, "DMARC", "fine", {}),
        ]

    client, _ = make_client(runner)
    r = client.get(f"{report_path(client)}/report.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    text = pdf_text(r.content)
    assert (
        "<b>bold</b>" in text and "<script>alert(1)</script>" in text
    )  # shown literally, not parsed
    assert text.count("x" * 50) >= 1 and "x" * 450 not in text  # long values are cut off


def test_pdf_with_no_score_and_with_errors_only():
    def runner(resolver, domain):
        return [Finding("spf", Status.ERROR, "SPF", "We could not complete this check.")]

    client, _ = make_client(runner)
    text = pdf_text(client.get(f"{report_path(client)}/report.pdf").content)
    assert "no score" in text and "COULD NOT CHECK" in text


def test_pdf_with_everything_passing():
    client, _ = make_client(canned_runner({"spf": Status.PASS, "dmarc": Status.PASS}))
    text = pdf_text(client.get(f"{report_path(client)}/report.pdf").content)
    assert "Nothing to fix" in text and "100" in text


def test_long_report_runs_over_several_pages():
    def runner(resolver, domain):
        return [
            Finding("spf", Status.WARN, f"Check {i}", "word " * 200, {"k": "v" * 300})
            for i in range(12)
        ]

    client, _ = make_client(runner)
    reader = PdfReader(io.BytesIO(client.get(f"{report_path(client)}/report.pdf").content))
    assert len(reader.pages) >= 3
    assert "Page 2" in reader.pages[1].extract_text()


def test_clean_escapes_markup_and_replaces_unsupported_characters():
    assert clean("<b>&") == "&lt;b&gt;&amp;"
    assert clean("café €") == "café €"  # in the base font's character set
    assert "日" not in clean("日本") and clean(None) == ""
