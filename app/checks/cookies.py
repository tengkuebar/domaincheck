"""Check 8: cookie flags on the home page response."""

from __future__ import annotations

from app.checks.base import Check, CheckContext, Finding, Status
from app.checks.web import main_page


def parse_set_cookie(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for p in parts[1:]:
        key, _, val = p.partition("=")
        attrs[key.strip().lower()] = val.strip()
    return {
        "name": name,
        "secure": "secure" in attrs or name.startswith(("__Secure-", "__Host-")),
        "httponly": "httponly" in attrs,
        "samesite": attrs.get("samesite") or None,
    }


def run(ctx: CheckContext) -> Finding:
    cid, title = "cookies", "Cookie flags"
    raw = main_page(ctx).headers.get_list("set-cookie")
    cookies = [parse_set_cookie(c) for c in raw]
    if not cookies:
        return Finding(cid, Status.PASS, title, "The home page does not set any cookies.", {})
    # Cookie values are never recorded, only names and flags.
    evidence = {"cookies": cookies}
    no_secure = [c["name"] for c in cookies if not c["secure"]]
    other = [c["name"] for c in cookies if not c["httponly"] or not c["samesite"]]
    if no_secure:
        return Finding(
            cid, Status.FAIL, title,
            "Cookies without the Secure flag can be sent over plain HTTP: "
            + ", ".join(no_secure)
            + ".",
            evidence,
        )  # fmt: skip
    if other:
        return Finding(
            cid, Status.WARN, title,
            "These cookies lack HttpOnly or SameSite: "
            + ", ".join(other)
            + ". HttpOnly is not needed for cookies that scripts must read, "
            "such as some analytics cookies.",
            evidence,
        )  # fmt: skip
    return Finding(
        cid, Status.PASS, title, "All cookies have Secure, HttpOnly and SameSite.", evidence
    )


CHECK = Check("cookies", "Cookie flags", run)
