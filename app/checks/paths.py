"""Check 10: a small fixed list of sensitive paths.

This sends real requests, so it only runs on verified domains (the scan is refused otherwise) and
the list below is a constant. It never grows from user input. A file only counts as exposed if
its content looks like the real thing, which avoids false alarms from pages that return 200 for
everything. Response bodies are never stored or logged.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from app.checks.base import Check, CheckContext, Finding, Status
from app.fetcher import FetchError


def _env(b: bytes) -> bool:
    return bool(re.search(rb"^[A-Z][A-Z0-9_]{2,}=.+", b, re.MULTILINE))


PATHS: tuple[tuple[str, Callable[[bytes], bool]], ...] = (
    ("/.git/HEAD", lambda b: b.lstrip().startswith(b"ref:")),
    ("/.git/config", lambda b: b"[core]" in b),
    ("/.env", _env),
    ("/.svn/entries", lambda b: re.match(rb"^\d+\s", b) is not None and b"dir" in b[:200]),
    ("/.DS_Store", lambda b: b.startswith(b"\x00\x00\x00\x01Bud1")),
    ("/wp-config.php.bak", lambda b: b"DB_PASSWORD" in b),
    ("/phpinfo.php", lambda b: b"PHP Version" in b or b"phpinfo()" in b),
    ("/server-status", lambda b: b"Apache Server Status" in b),
    ("/backup.zip", lambda b: b.startswith(b"PK")),
    ("/database.sql", lambda b: b"CREATE TABLE" in b or b"INSERT INTO" in b),
)


def run(ctx: CheckContext) -> Finding:
    cid, title = "paths", "Exposed sensitive files"
    if ctx.fetcher is None:
        raise FetchError("No fetcher available.")
    exposed: list[str] = []
    failures = 0
    for path, looks_real in PATHS:
        try:
            r = ctx.fetcher.fetch(f"https://{ctx.domain}{path}", max_redirects=0)
        except FetchError:
            failures += 1
            continue
        if r.status == 200 and looks_real(r.body):
            exposed.append(path)
    if failures == len(PATHS):
        raise FetchError("Could not reach the site")
    evidence = {"paths_checked": [p for p, _ in PATHS], "exposed": exposed}
    if exposed:
        return Finding(
            cid, Status.FAIL, title,
            "These files can be downloaded by anyone and may contain secrets or source code: "
            + ", ".join(exposed) + ". Treat any passwords in them as leaked.",
            evidence,
        )  # fmt: skip
    return Finding(
        cid, Status.PASS, title,
        f"None of {len(PATHS)} commonly exposed files were reachable.",
        evidence,
    )  # fmt: skip


CHECK = Check("paths", "Exposed sensitive files", run)
