"""The rate limiter: at most N requests in any rolling window, and a floor between two requests.

A publisher states its limit as a count in a rolling window (the NVD: 5 requests in any 30 seconds
without a key, 50 with one). The limiter keeps the start time of every request still inside the
window and makes the caller wait until one leaves, so no rolling window ever holds more than the
count, whatever the burst. A margin widens the window slightly, because the publisher counts a
request when it arrives and we count it when it leaves. The clock and the sleep are injected, so
the tests drive it with a fake clock and assert the property directly.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Limit:
    requests: int
    window_s: float
    min_interval_s: float = 0.0
    margin: float = 0.05

    def __post_init__(self) -> None:
        if self.requests < 1:
            raise ValueError("a limit allows at least one request")
        if self.window_s <= 0:
            raise ValueError("a limit has a positive window")
        if self.min_interval_s < 0 or self.margin < 0:
            raise ValueError("an interval and a margin are never negative")

    @property
    def effective_window_s(self) -> float:
        return self.window_s * (1.0 + self.margin)


class RateLimiter:
    """Thread safe. `acquire` blocks until a request may start, records it, and returns the wait."""

    def __init__(
        self,
        limit: Limit,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.limit = limit
        self._clock = clock
        self._sleep = sleep
        self._starts: deque[float] = deque()
        self._lock = threading.Lock()
        self.waited_s = 0.0
        self.count = 0

    def _delay(self, now: float) -> float:
        window = self.limit.effective_window_s
        while self._starts and now - self._starts[0] >= window:
            self._starts.popleft()
        delay = 0.0
        if len(self._starts) >= self.limit.requests:
            delay = self._starts[0] + window - now
        if self._starts and self.limit.min_interval_s > 0:
            delay = max(delay, self._starts[-1] + self.limit.min_interval_s - now)
        return max(delay, 0.0)

    def acquire(self) -> float:
        waited = 0.0
        with self._lock:
            while True:
                now = self._clock()
                delay = self._delay(now)
                if delay <= 0:
                    self._starts.append(now)
                    self.count += 1
                    self.waited_s += waited
                    return waited
                self._sleep(delay)
                waited += delay

    def starts(self) -> list[float]:
        with self._lock:
            return list(self._starts)


def max_in_any_window(starts: list[float], window_s: float) -> int:
    """The most request starts that fall inside any half open window of the given length."""
    ordered = sorted(starts)
    best = 0
    left = 0
    for right, value in enumerate(ordered):
        while value - ordered[left] >= window_s:
            left += 1
        best = max(best, right - left + 1)
    return best
