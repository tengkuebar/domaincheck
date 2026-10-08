"""Check interface. Each check is its own module exposing a ``CHECK`` (NFR-08).

A check takes a context and returns a Finding. It must not open its own sockets: DNS goes through
``ctx.resolver`` and HTTP through ``ctx.fetcher``.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.dns import Resolver
from app.fetcher import SafeFetcher


class Status(enum.StrEnum):
    PASS = "pass"  # noqa: S105  # nosec B105 - a status name, not a credential
    WARN = "warn"
    FAIL = "fail"
    NOT_DETECTED = "not_detected"
    ERROR = "error"  # the check could not complete; excluded from the score


@dataclass
class Finding:
    check_id: str
    status: Status
    title: str
    explanation: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckContext:
    domain: str
    resolver: Resolver
    fetcher: SafeFetcher | None = None
    cache: dict[str, Any] = field(default_factory=dict)  # per-scan, shared between checks


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    run: Callable[[CheckContext], Finding]


_SEVERITY = {Status.PASS: 0, Status.NOT_DETECTED: 1, Status.WARN: 2, Status.FAIL: 3}


def worst(statuses: list[Status]) -> Status:
    return max(statuses, key=lambda s: _SEVERITY.get(s, 0))
