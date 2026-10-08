"""The numbers and grouping behind a report. Shared by the web page and the PDF export."""

from __future__ import annotations

from typing import Any

from app.checks.base import Finding
from app.fixes.library import fix_steps
from app.scanning.store import ScanResult
from app.scoring import band, category_scores, gains, projected_score, weight_for

_ORDER = {"fail": 0, "warn": 1, "not_detected": 2, "pass": 3, "error": 4}  # nosec B105
_ATTENTION = ("fail", "warn", "not_detected")


def short_title(finding: Finding) -> str:
    return finding.title.split(" (")[0]


def build_dashboard(result: ScanResult) -> dict[str, Any]:
    """Everything a report needs, computed once so the template and PDF stay simple."""
    findings = result.findings
    gain_by_check = gains(findings)

    def row(f: Finding) -> dict[str, Any]:
        gain = gain_by_check.get(f.check_id, 0.0)
        return {
            "finding": f,
            "short": short_title(f),
            "fix": fix_steps(f.check_id, f.status),
            "gain": round(gain, 1),
            "weight": weight_for(f.check_id),
        }

    rows = sorted(
        (row(f) for f in findings), key=lambda r: (_ORDER[r["finding"].status], -r["gain"])
    )
    by_id = {r["finding"].check_id: r for r in rows}

    categories = []
    for cat in category_scores(findings):
        categories.append(
            {
                **cat,
                "band": band(cat["pct"]),
                "rows": [by_id[f.check_id] for f in cat["findings"]],
            }
        )

    fix_first = [
        {
            "rank": i + 1,
            "title": r["short"],
            "action": r["fix"]["action"] if r["fix"] else "",
            "effort": r["fix"]["effort"] if r["fix"] else "",
            "gain": r["gain"],
        }
        for i, r in enumerate(
            sorted((r for r in rows if r["gain"] > 0), key=lambda r: -r["gain"])[:4]
        )
    ]

    scored = [r for r in rows if r["finding"].status != "error"]
    max_weight = max((r["weight"] for r in scored), default=1)
    weights = [
        {"short": r["short"], "weight": r["weight"], "pct": round(100 * r["weight"] / max_weight)}
        for r in sorted(scored, key=lambda r: -r["weight"])
    ]

    count = lambda s: sum(r["finding"].status == s for r in rows)  # noqa: E731
    score = result.score
    weakest = min(
        (c for c in categories if c["pct"] is not None), key=lambda c: c["pct"], default=None
    )
    return {
        "score": score,
        "band": band(score),
        "score_after": projected_score(findings),
        "counts": {s: count(s) for s in ("fail", "warn", "not_detected", "pass", "error")},
        "attention_count": sum(count(s) for s in _ATTENTION),
        "categories": categories,
        "weakest": weakest,
        "fix_first": fix_first,
        "weights": weights,
        "rows": rows,
        "first_open": next((r["finding"].check_id for r in rows if r["gain"] > 0), None),
    }
