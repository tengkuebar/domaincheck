"""Check 7: browser security headers on the home page."""

from __future__ import annotations

import re

from app.checks.base import Check, CheckContext, Finding, Status
from app.checks.web import main_page

_GOOD_REFERRER = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "origin",
    "origin-when-cross-origin",
}


def _directive(csp: str, name: str) -> str | None:
    for part in csp.split(";"):
        bits = part.split()
        if bits and bits[0].lower() == name:
            return " ".join(bits[1:])
    return None


def judge_csp(value: str | None) -> tuple[str, str]:
    if not value:
        return "missing", "No Content-Security-Policy."
    scripts = _directive(value, "script-src") or _directive(value, "default-src") or ""
    low = scripts.lower()
    if "'unsafe-inline'" in low or "'unsafe-eval'" in low:
        return "weak", "Allows unsafe-inline or unsafe-eval scripts."
    if re.search(r"(^|\s)\*(\s|$)", scripts) or "http:" in low.split():
        return "weak", "Allows scripts from any origin."
    if not scripts:
        return "weak", "No script-src or default-src directive."
    return "ok", ""


def judge_xfo(value: str | None, csp: str | None) -> tuple[str, str]:
    if csp and _directive(csp, "frame-ancestors") is not None:
        return "ok", ""
    if not value:
        return "missing", "No X-Frame-Options or frame-ancestors."
    v = value.strip().upper()
    if v in ("DENY", "SAMEORIGIN"):
        return "ok", ""
    return "weak", "Value is obsolete or not recognised."


def judge_xcto(value: str | None) -> tuple[str, str]:
    if not value:
        return "missing", "No X-Content-Type-Options."
    return ("ok", "") if value.strip().lower() == "nosniff" else ("weak", "Should be nosniff.")


def judge_referrer(value: str | None) -> tuple[str, str]:
    if not value:
        return "missing", "No Referrer-Policy."
    last = value.split(",")[-1].strip().lower()  # the last recognised value wins
    return ("ok", "") if last in _GOOD_REFERRER else ("weak", "Leaks full URLs to other sites.")


def judge_permissions(value: str | None) -> tuple[str, str]:
    return ("ok", "") if value else ("missing", "No Permissions-Policy.")


def run(ctx: CheckContext) -> Finding:
    cid, title = "headers", "Security headers"
    h = main_page(ctx).headers
    csp = h.get("content-security-policy")
    verdicts = {
        "Content-Security-Policy": judge_csp(csp),
        "X-Frame-Options": judge_xfo(h.get("x-frame-options"), csp),
        "X-Content-Type-Options": judge_xcto(h.get("x-content-type-options")),
        "Referrer-Policy": judge_referrer(h.get("referrer-policy")),
        "Permissions-Policy": judge_permissions(h.get("permissions-policy")),
    }
    missing = [n for n, (v, _) in verdicts.items() if v == "missing"]
    weak = [n for n, (v, _) in verdicts.items() if v == "weak"]
    evidence = {
        n: {"verdict": v, "note": note or None, "value": h.get(n.lower())}
        for n, (v, note) in verdicts.items()
    }
    if not missing and not weak:
        return Finding(cid, Status.PASS, title, "All five security headers are set well.", evidence)
    parts = []
    if missing:
        parts.append("Missing: " + ", ".join(missing) + ".")
    if weak:
        parts.append("Weak: " + ", ".join(weak) + ".")
    status = Status.FAIL if len(missing) >= 3 else Status.WARN
    return Finding(cid, status, title, " ".join(parts), evidence)


CHECK = Check("headers", "Security headers", run)
