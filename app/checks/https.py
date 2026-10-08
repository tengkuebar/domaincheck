"""Check 6: HTTP redirects to HTTPS, and HSTS is set on the HTTPS site."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from app.checks.base import Check, CheckContext, Finding, Status
from app.checks.web import main_page
from app.fetcher import FetchError

MIN_HSTS_SECONDS = 15_552_000  # 180 days
_REDIRECTS = (301, 302, 303, 307, 308)


def parse_hsts(value: str | None) -> dict | None:
    if not value:
        return None
    max_age = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
    return {
        "max_age": int(max_age.group(1)) if max_age else None,
        "include_subdomains": bool(re.search(r"includeSubDomains", value, re.IGNORECASE)),
        "preload": bool(re.search(r"\bpreload\b", value, re.IGNORECASE)),
    }


def run(ctx: CheckContext) -> Finding:
    cid, title = "https", "HTTPS redirect and HSTS"
    page = main_page(ctx)  # raises FetchError if HTTPS does not work at all
    if ctx.fetcher is None:
        raise FetchError("No fetcher available.")
    evidence: dict = {}
    problems: list[str] = []
    notes: list[str] = []

    # HTTP -> HTTPS
    try:
        first = ctx.fetcher.fetch(f"http://{ctx.domain}/", max_redirects=0)
    except FetchError:
        evidence["http"] = "port 80 not reachable"
        notes.append("Plain HTTP is not reachable, so visitors typing http:// get an error.")
    else:
        location = first.headers.get("location")
        target = urljoin(first.url, location) if location else None
        evidence["http"] = {"status": first.status, "location": target}
        if first.status in _REDIRECTS and target and urlsplit(target).scheme == "https":
            pass
        elif first.status in _REDIRECTS:
            problems.append("HTTP redirects to another plain HTTP address.")
        else:
            problems.append("The site is served over plain HTTP without redirecting to HTTPS.")

    # HSTS (on the final HTTPS response)
    hsts = parse_hsts(page.headers.get("strict-transport-security"))
    evidence["hsts"] = hsts
    hsts_ok = True
    if hsts is None or not hsts["max_age"]:
        hsts_ok = False
        notes.append("No usable HSTS header, so browsers are not told to always use HTTPS.")
    elif hsts["max_age"] < MIN_HSTS_SECONDS:
        hsts_ok = False
        notes.append("HSTS max-age is under 180 days; a longer period is recommended.")

    if problems:
        return Finding(cid, Status.FAIL, title, " ".join(problems + notes), evidence)
    if not hsts_ok or notes:
        return Finding(cid, Status.WARN, title, " ".join(notes), evidence)
    return Finding(
        cid,
        Status.PASS,
        title,
        "HTTP redirects to HTTPS and HSTS is set with a long lifetime.",
        evidence,
    )


CHECK = Check("https", "HTTPS redirect and HSTS", run)
