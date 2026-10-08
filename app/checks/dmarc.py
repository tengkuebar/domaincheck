"""Check 2: DMARC exists, its policy level, and whether a reporting address is set."""

from __future__ import annotations

import re

from app.checks.base import Check, CheckContext, Finding, Status

_DMARC_START = re.compile(r"^\s*v=DMARC1\s*(;|$)", re.IGNORECASE)


def parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags.setdefault(key.strip().lower(), value.strip())
    return tags


def run(ctx: CheckContext) -> Finding:
    cid, title = "dmarc", "DMARC (what receivers do with forged mail)"
    values = ctx.resolver.query(f"_dmarc.{ctx.domain}", "TXT")
    records = [v.strip() for v in values if _DMARC_START.match(v)]
    if not records:
        return Finding(
            cid, Status.FAIL, title,
            "No DMARC record was found. Receivers have no instructions for mail that fails "
            "SPF and DKIM, and you get no reports about spoofing of your domain.",
        )  # fmt: skip
    if len(records) > 1:
        return Finding(
            cid, Status.FAIL, title,
            "More than one DMARC record was found, which makes DMARC invalid. Keep one.",
            {"records": records},
        )  # fmt: skip

    tags = parse_tags(records[0])
    policy = tags.get("p", "").lower()
    rua = tags.get("rua", "")
    has_reporting = "mailto:" in rua.lower()
    pct_raw = tags.get("pct", "100")
    pct = int(pct_raw) if pct_raw.isdigit() else 100
    evidence = {
        "record": records[0],
        "policy": policy or None,
        "reporting_address": rua or None,
        "pct": pct,
    }
    report_note = (
        "" if has_reporting
        else " No reporting address (rua) is set, so you will not see who sends as your domain."
    )  # fmt: skip

    if policy not in ("none", "quarantine", "reject"):
        return Finding(
            cid, Status.FAIL, title,
            "The DMARC record has a missing or invalid policy (p=), so receivers will ignore it.",
            evidence,
        )  # fmt: skip
    if policy == "none":
        return Finding(
            cid, Status.WARN, title,
            "DMARC is in monitoring mode (p=none). It reports problems but does not stop "
            "forged mail." + report_note,
            evidence,
        )  # fmt: skip
    if pct < 100:
        return Finding(
            cid, Status.WARN, title,
            f"DMARC policy is {policy}, but only applies to {pct}% of mail.{report_note}",
            evidence,
        )  # fmt: skip
    return Finding(
        cid, Status.PASS, title,
        f"DMARC is enforcing (p={policy}).{report_note}",
        evidence,
    )  # fmt: skip


CHECK = Check("dmarc", "DMARC", run)
