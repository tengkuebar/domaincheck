"""In-memory scan results. Nothing is written to disk; results expire and vanish on restart."""

from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

from app.checks.base import Finding

RESULT_TTL = 3600.0
MAX_RESULTS = 500


@dataclass
class ScanResult:
    id: str
    domain: str
    created_at: float
    status: str = "queued"  # queued | running | done | failed
    score: int | None = None
    findings: list[Finding] = field(default_factory=list)


class ResultStore:
    def __init__(
        self,
        ttl: float = RESULT_TTL,
        max_items: int = MAX_RESULTS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._ttl = ttl
        self._max = max_items
        self._clock = clock
        self._items: OrderedDict[str, ScanResult] = OrderedDict()
        self._lock = threading.Lock()

    def _expire(self) -> None:
        cutoff = self._clock() - self._ttl
        while self._items:
            oldest = next(iter(self._items.values()))
            if oldest.created_at > cutoff and len(self._items) < self._max:
                break
            self._items.popitem(last=False)

    def create(self, domain: str) -> ScanResult:
        with self._lock:
            self._expire()
            # Unguessable id: anyone with the link can read the report, nobody else can find it.
            result = ScanResult(secrets.token_urlsafe(16), domain, self._clock())
            self._items[result.id] = result
            return result

    def get(self, scan_id: str) -> ScanResult | None:
        with self._lock:
            self._expire()
            return self._items.get(scan_id)
