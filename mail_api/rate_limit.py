from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass

from .db import get_conn


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


class SqliteFixedWindowRateLimiter:
    def __init__(
        self,
        *,
        scope: str,
        max_requests: int,
        window_seconds: int,
    ) -> None:
        self._scope = scope.strip() or "default"
        self._max = int(max_requests)
        self._window = int(window_seconds)

    def check(self, *, key: str) -> RateLimitResult:
        now = int(time.time())
        window_start = now - (now % self._window)
        k = (key or "").strip()
        if not k:
            return RateLimitResult(ok=False, retry_after_seconds=self._window)

        with get_conn() as conn:
            row = conn.execute(
                (
                    "select window_start, count "
                    "from rate_limit_windows where scope = ? and key = ?"
                ),
                (self._scope, k),
            ).fetchone()

            if row is None:
                count = 1
                conn.execute(
                    (
                        "insert into rate_limit_windows(" 
                        "scope, key, window_start, count" 
                        ") values(?, ?, ?, ?)"
                    ),
                    (self._scope, k, window_start, count),
                )
                conn.commit()
            else:
                prev_start = int(row["window_start"])
                prev_count = int(row["count"])
                if prev_start != window_start:
                    count = 1
                else:
                    count = prev_count + 1
                conn.execute(
                    (
                        "update rate_limit_windows "
                        "set window_start = ?, count = ? "
                        "where scope = ? and key = ?"
                    ),
                    (window_start, count, self._scope, k),
                )
                conn.commit()

        if count > self._max:
            retry_after = (window_start + self._window) - now
            return RateLimitResult(ok=False, retry_after_seconds=int(retry_after))

        return RateLimitResult(ok=True, retry_after_seconds=0)
