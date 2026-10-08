"""Check 1: SPF exists, is unique, ends sensibly, and stays within the 10 DNS lookup limit."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.checks.base import Check, CheckContext, Finding, Status
from app.dns import Resolver

MAX_LOOKUPS = 10
_SPF_START = re.compile(r"^v=spf1(\s|$)", re.IGNORECASE)
_MECH = re.compile(r"^[+\-~?]?(include|a|mx|ptr|exists)(?=[:/]|$)", re.IGNORECASE)
_ALL = re.compile(r"^([+\-~?]?)all$", re.IGNORECASE)


def find_spf_records(txt_values: list[str]) -> list[str]:
    return [v.strip() for v in txt_values if _SPF_START.match(v.strip())]


@dataclass
class _Walk:
    resolver: Resolver
    lookups: int = 0
    uses_ptr: bool = False
    problems: list[str] = field(default_factory=list)
    seen: set[str] = field(default_factory=set)


def _walk(state: _Walk, domain: str, record: str) -> str | None:
    """Count lookups in ``record``. Returns the record's own ``all`` qualifier (or via redirect)."""
    state.seen.add(domain)
    final: str | None = None
    redirect: str | None = None
    for term in record.split()[1:]:
        low = term.lower()
        all_match = _ALL.match(low)
        if all_match:
            final = all_match.group(1) or "+"
            continue
        if low.startswith("redirect="):
            redirect = term.split("=", 1)[1]
            state.lookups += 1
            continue
        mech = _MECH.match(low)
        if not mech:
            continue
        kind = mech.group(1)
        state.lookups += 1
        if kind == "ptr":
            state.uses_ptr = True
        if kind == "include":
            target = term.split(":", 1)[1].rstrip(".").lower() if ":" in term else ""
            if not target:
                state.problems.append("An include has no domain.")
            elif "%" not in target and state.lookups <= MAX_LOOKUPS:
                _follow(state, target)
    if final is None and redirect and "%" not in redirect and state.lookups <= MAX_LOOKUPS:
        return _follow(state, redirect.rstrip(".").lower())
    return final


def _follow(state: _Walk, target: str) -> str | None:
    if target in state.seen:
        state.problems.append(f"{target} refers back to a domain already in the chain (loop).")
        return None
    records = find_spf_records(state.resolver.query(target, "TXT"))
    if len(records) != 1:
        what = "has no SPF record" if not records else "has more than one SPF record"
        state.problems.append(f"{target} {what}.")
        return None
    return _walk(state, target, records[0])


def run(ctx: CheckContext) -> Finding:
    records = find_spf_records(ctx.resolver.query(ctx.domain, "TXT"))
    cid, title = "spf", "SPF (who may send email as your domain)"
    if not records:
        return Finding(
            cid, Status.FAIL, title,
            "No SPF record was found. Without one, anyone can more easily send email that "
            "looks like it came from your domain.",
        )  # fmt: skip
    if len(records) > 1:
        return Finding(
            cid, Status.FAIL, title,
            "More than one SPF record was found. Receivers treat this as an error and may "
            "ignore SPF entirely. Merge them into a single record.",
            {"records": records},
        )  # fmt: skip

    record = records[0]
    state = _Walk(ctx.resolver)
    final = _walk(state, ctx.domain, record)
    evidence = {
        "record": record,
        "dns_lookups": state.lookups,
        "all": f"{final or ''}all" if final else None,
    }

    problems = list(state.problems)
    if state.lookups > MAX_LOOKUPS:
        problems.append(
            f"The record needs {state.lookups} DNS lookups; the limit is {MAX_LOOKUPS}."
        )
    if problems:
        evidence["problems"] = problems
        return Finding(
            cid, Status.FAIL, title,
            "The SPF record is broken or too complex, so receivers may reject it as an "
            "error: " + " ".join(problems),
            evidence,
        )  # fmt: skip
    if final is None:
        return Finding(
            cid, Status.FAIL, title,
            "The SPF record does not end with an 'all' rule, so it does not say what to do "
            "with mail from other senders.",
            evidence,
        )  # fmt: skip
    if final in ("+", "?"):
        return Finding(
            cid, Status.FAIL, title,
            f"The record ends with '{final}all', which allows or ignores mail from any sender. "
            "It should end with '-all' (reject) or '~all' (mark as suspicious).",
            evidence,
        )  # fmt: skip
    notes: list[str] = []
    status = Status.PASS
    if state.uses_ptr:
        status = Status.WARN
        notes.append("It uses the 'ptr' rule, which is deprecated and slow.")
    if state.lookups >= MAX_LOOKUPS:
        status = Status.WARN
        notes.append("It is exactly at the 10 lookup limit, so adding a sender will break it.")
    if final == "~":
        notes.append("'~all' marks other mail as suspicious; '-all' is stricter.")
    return Finding(
        cid, status, title,
        "An SPF record is published and valid. " + " ".join(notes),
        evidence,
    )  # fmt: skip


CHECK = Check("spf", "SPF", run)
