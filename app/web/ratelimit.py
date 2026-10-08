"""Small in-memory sliding-window limiter (SR-08). Per process; fine for a single instance."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable


class RateLimiter:
    def __init__(
        self, limit: int, window_seconds: float, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.limit = limit
        self.window = window_seconds
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str) -> deque[float]:
        hits = self._hits[key]
        cutoff = self._clock() - self.window
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if not hits:
            self._hits.pop(key, None)
            return deque()
        return hits

    def allowed(self, key: str) -> bool:
        with self._lock:
            return len(self._prune(key)) < self.limit

    def record(self, key: str) -> None:
        with self._lock:
            self._prune(key)
            self._hits[key].append(self._clock())

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def hit(self, key: str) -> bool:
        """Record an attempt and return whether it is within the limit."""
        with self._lock:
            hits = self._prune(key)
            if len(hits) >= self.limit:
                return False
            self._hits[key].append(self._clock())
            return True


class Limiters:
    def __init__(self, per_ip: int = 10, per_domain: int = 3, global_: int = 120) -> None:
        self.scan_ip = RateLimiter(per_ip, 3600)
        self.scan_domain = RateLimiter(per_domain, 3600)  # protects the target from being hammered
        self.scan_global = RateLimiter(global_, 3600)
