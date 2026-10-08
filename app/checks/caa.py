"""Check 9: CAA records limit which authorities may issue certificates for the domain."""

from __future__ import annotations

from app.checks.base import Check, CheckContext, Finding, Status


def run(ctx: CheckContext) -> Finding:
    cid, title = "caa", "CAA (who may issue certificates)"
    records = ctx.resolver.query(ctx.domain, "CAA")
    if not records:
        return Finding(
            cid, Status.WARN, title,
            "No CAA record was found. Any certificate authority may issue certificates for your "
            "domain. A CAA record is optional hardening that narrows this to the ones you use.",
        )  # fmt: skip
    issuers = [r for r in records if " issue" in r.lower() or r.lower().startswith("issue")]
    return Finding(
        cid, Status.PASS, title,
        "A CAA record restricts which authorities may issue certificates." if issuers
        else "A CAA record is present (it sets no issue rules, so it limits little).",
        {"records": records},
    )  # fmt: skip


CHECK = Check("caa", "CAA", run)
