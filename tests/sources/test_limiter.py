"""The rate limiter under a burst: no rolling window ever holds more requests than the limit."""

from __future__ import annotations

import itertools
import threading
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from unscheduled_sources.limiter import Limit, RateLimiter, max_in_any_window


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def test_a_burst_of_twenty_five_never_puts_more_than_five_in_thirty_seconds() -> None:
    clock = FakeClock()
    limiter = RateLimiter(Limit(requests=5, window_s=30.0, margin=0.0), clock=clock, sleep=clock.sleep)
    starts = []
    for _ in range(25):
        limiter.acquire()
        starts.append(clock.now)
    assert max_in_any_window(starts, 30.0) == 5
    # Five windows of five: the burst takes four full windows to drain.
    assert starts[-1] - starts[0] >= 4 * 30.0
    assert limiter.count == 25


def test_the_margin_widens_the_window() -> None:
    clock = FakeClock()
    limiter = RateLimiter(Limit(requests=5, window_s=30.0, margin=0.1), clock=clock, sleep=clock.sleep)
    starts = []
    for _ in range(10):
        limiter.acquire()
        starts.append(clock.now)
    assert starts[5] - starts[0] == pytest.approx(33.0)


def test_the_floor_between_requests_holds() -> None:
    clock = FakeClock()
    limiter = RateLimiter(
        Limit(requests=100, window_s=1.0, min_interval_s=0.5), clock=clock, sleep=clock.sleep
    )
    starts = []
    for _ in range(4):
        limiter.acquire()
        starts.append(clock.now)
    gaps = [b - a for a, b in itertools.pairwise(starts)]
    assert all(g >= 0.5 for g in gaps)


@settings(max_examples=60, deadline=None)
@given(
    requests=st.integers(min_value=1, max_value=8),
    window=st.floats(min_value=0.5, max_value=60.0),
    burst=st.integers(min_value=1, max_value=40),
    pauses=st.lists(st.floats(min_value=0.0, max_value=20.0), min_size=0, max_size=40),
)
def test_no_window_ever_exceeds_the_limit(
    requests: int, window: float, burst: int, pauses: list[float]
) -> None:
    clock = FakeClock()
    limiter = RateLimiter(
        Limit(requests=requests, window_s=window, margin=0.0), clock=clock, sleep=clock.sleep
    )
    starts = []
    for i in range(burst):
        limiter.acquire()
        starts.append(clock.now)
        if i < len(pauses):
            clock.now += pauses[i]
    assert max_in_any_window(starts, window) <= requests


def test_threads_share_one_limit() -> None:
    limiter = RateLimiter(Limit(requests=3, window_s=0.2, margin=0.0))
    starts: list[float] = []
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(3):
            limiter.acquire()
            with lock:
                starts.append(time.monotonic())

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(starts) == 9
    # A little slack for the scheduler: the limiter itself guarantees three per window.
    assert max_in_any_window(starts, 0.19) <= 3


def test_a_limit_must_allow_something() -> None:
    with pytest.raises(ValueError):
        Limit(requests=0, window_s=30.0)
    with pytest.raises(ValueError):
        Limit(requests=5, window_s=0.0)
