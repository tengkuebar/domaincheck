"""Scoring (FR-08). Weights are a judgement call and are adjustable.

Pass counts 1, warn 0.5, fail 0. 'Not detected' counts as warn (DKIM only). 'Error' findings are
left out so a failed lookup does not lower the score. Score is the weighted share, 0 to 100.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from app.checks.base import Finding, Status

WEIGHTS: dict[str, int] = {
    "spf": 15,
    "dmarc": 20,
    "dkim": 10,
    "https": 15,
    "headers": 10,
    "cookies": 5,
    "caa": 5,
    "paths": 15,
    "tls_cert": 15,
    "tls_versions": 10,
}
DEFAULT_WEIGHT = 10
POINTS = {Status.PASS: 1.0, Status.WARN: 0.5, Status.NOT_DETECTED: 0.5, Status.FAIL: 0.0}


@dataclass(frozen=True)
class Category:
    key: str
    name: str
    blurb: str
    check_ids: tuple[str, ...]


CATEGORIES = (
    Category(
        "email", "Email protection", "Stops others sending mail as you.", ("spf", "dmarc", "dkim")
    ),
    Category(
        "encryption",
        "Encryption and HTTPS",
        "Keeps visits private and trusted.",
        ("tls_cert", "tls_versions", "https"),
    ),
    Category(
        "hardening",
        "Website hardening",
        "Browser protections and certificate controls.",
        ("headers", "cookies", "caa", "paths"),
    ),
)


def weight_for(check_id: str) -> int:
    return WEIGHTS.get(check_id, DEFAULT_WEIGHT)


def _scored(findings: Iterable[Finding]) -> list[Finding]:
    return [f for f in findings if f.status in POINTS]


def _percent(findings: list[Finding]) -> int | None:
    total = sum(weight_for(f.check_id) for f in findings)
    if total == 0:
        return None
    earned = sum(weight_for(f.check_id) * POINTS[f.status] for f in findings)
    return round(100 * earned / total)


def score(findings: Iterable[Finding]) -> int | None:
    """Return 0-100, or None if no finding could be scored."""
    return _percent(_scored(findings))


def gains(findings: Iterable[Finding]) -> dict[str, float]:
    """Score points each finding would add if it passed, on the same 0-100 scale as the score."""
    scored = _scored(findings)
    total = sum(weight_for(f.check_id) for f in scored)
    if total == 0:
        return {}
    return {
        f.check_id: 100 * weight_for(f.check_id) * (1 - POINTS[f.status]) / total for f in scored
    }


def projected_score(findings: Iterable[Finding], top_n: int = 3) -> int | None:
    """The score if the ``top_n`` most valuable fixes were made."""
    findings = list(findings)
    current = score(findings)
    if current is None:
        return None
    best = sorted(gains(findings).values(), reverse=True)[:top_n]
    scored = _scored(findings)
    total = sum(weight_for(f.check_id) for f in scored)
    earned = sum(weight_for(f.check_id) * POINTS[f.status] for f in scored)
    return min(100, round(100 * earned / total + sum(best)))


def category_scores(findings: Iterable[Finding]) -> list[dict]:
    """Per-area percentage over the findings that could be scored. ``pct`` is None if none were."""
    findings = list(findings)
    out = []
    for cat in CATEGORIES:
        members = [f for f in findings if f.check_id in cat.check_ids]
        if not members:
            continue
        out.append(
            {
                "key": cat.key,
                "name": cat.name,
                "blurb": cat.blurb,
                "pct": _percent(_scored(members)),
                "findings": members,
            }
        )
    return out


def band(pct: int | None) -> tuple[str, str] | None:
    """(css class, label) for a 0-100 value."""
    if pct is None:
        return None
    if pct >= 85:
        return ("good", "Strong")
    if pct >= 60:
        return ("warn", "Fair")
    return ("bad", "Needs work")
