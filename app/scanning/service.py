"""Run scans in the background and keep results in memory."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from app.checks.base import CheckContext, Finding
from app.checks.engine import run_checks
from app.dns import Resolver
from app.fetcher import SafeFetcher
from app.scanning.store import ResultStore
from app.scoring import score

log = logging.getLogger(__name__)

Runner = Callable[[Resolver, str], list[Finding]]
MAX_PENDING = 20


def default_runner(resolver: Resolver, domain: str) -> list[Finding]:
    ctx = CheckContext(domain=domain, resolver=resolver, fetcher=SafeFetcher(resolver))
    return run_checks(ctx)


def execute_scan(store: ResultStore, resolver: Resolver, scan_id: str, runner: Runner) -> None:
    result = store.get(scan_id)
    if result is None:
        return
    result.status = "running"
    try:
        findings = runner(resolver, result.domain)
    except Exception:
        log.exception("scan failed")
        result.status = "failed"
        return
    result.findings = findings
    result.score = score(findings)
    result.status = "done"


class JobRunner:
    """Small thread pool with a cap on waiting scans, so a flood cannot pile up work."""

    def __init__(
        self,
        store: ResultStore,
        resolver: Resolver,
        runner: Runner = default_runner,
        workers: int = 2,
        synchronous: bool = False,
    ) -> None:
        self._store = store
        self._resolver = resolver
        self._runner = runner
        self._synchronous = synchronous  # tests run scans inline for determinism
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan")
        self._pending = 0
        self._lock = threading.Lock()

    def submit(self, scan_id: str) -> bool:
        """Queue a scan. Returns False if too many are already waiting."""
        with self._lock:
            if self._pending >= MAX_PENDING:
                return False
            self._pending += 1
        if self._synchronous:
            self._run(scan_id)
        else:
            self._pool.submit(self._run, scan_id)
        return True

    def _run(self, scan_id: str) -> None:
        try:
            execute_scan(self._store, self._resolver, scan_id, self._runner)
        finally:
            with self._lock:
                self._pending -= 1
