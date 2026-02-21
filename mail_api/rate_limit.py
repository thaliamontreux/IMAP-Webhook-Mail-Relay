from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass


@dataclass
class RateLimitResult:
    ok: bool
    retry_after_seconds: int


class SlidingWindowRateLimiter:
    def __init__(self, *, max_requests: int, window_seconds: int) -> None:
        self._max = int(max_requests)
        self._window = float(window_seconds)
        self._hits: dict[str, deque[float]] = {}

    def check(self, *, key: str) -> RateLimitResult:
        now = time.monotonic()
        q = self._hits.get(key)
        if q is None:
            q = deque()
            self._hits[key] = q

        cutoff = now - self._window
        while q and q[0] < cutoff:
            q.popleft()

        if len(q) >= self._max:
            retry_after = int(max(1.0, (q[0] + self._window) - now))
            return RateLimitResult(ok=False, retry_after_seconds=retry_after)

        q.append(now)
        return RateLimitResult(ok=True, retry_after_seconds=0)
