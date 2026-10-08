"""Scan engine: runs checks in order inside a time budget and collects findings (NFR-01)."""

from __future__ import annotations

import logging
import time

from app.checks import (
    caa,
    cookies,
    dkim,
    dmarc,
    headers,
    https,
    paths,
    spf,
    tls_cert,
    tls_versions,
)
from app.checks.base import Check, CheckContext, Finding, Status
from app.dns import DnsError
from app.fetcher import FetchError

log = logging.getLogger(__name__)

ALL_CHECKS: list[Check] = [
    spf.CHECK,
    dmarc.CHECK,
    dkim.CHECK,
    tls_cert.CHECK,
    tls_versions.CHECK,
    https.CHECK,
    headers.CHECK,
    cookies.CHECK,
    caa.CHECK,
]
# Requests sensitive file paths on the target, so it is opt-in (DOMAINCHECK_ENABLE_PATH_CHECK).
OPTIONAL_CHECKS: list[Check] = [paths.CHECK]
SCAN_BUDGET = 60.0
_path_check_enabled = False


def set_path_check_enabled(enabled: bool) -> None:
    global _path_check_enabled
    _path_check_enabled = enabled


def active_checks() -> list[Check]:
    return ALL_CHECKS + (OPTIONAL_CHECKS if _path_check_enabled else [])


def run_checks(
    ctx: CheckContext, checks: list[Check] | None = None, budget: float = SCAN_BUDGET
) -> list[Finding]:
    deadline = time.monotonic() + budget
    findings: list[Finding] = []
    for check in checks if checks is not None else active_checks():
        if time.monotonic() > deadline:
            findings.append(_error(check, "The scan ran out of time before this check."))
            continue
        try:
            findings.append(check.run(ctx))
        except (DnsError, FetchError) as exc:
            log.info("check %s could not complete: %s", check.id, type(exc).__name__)
            findings.append(_error(check, "We could not complete this check (lookup failed)."))
        except Exception:
            log.exception("check %s crashed", check.id)
            findings.append(_error(check, "This check hit an internal error."))
    return findings


def _error(check: Check, message: str) -> Finding:
    return Finding(check.id, Status.ERROR, check.title, message)
