"""HTTP for every fetcher: one client, the project User-Agent, retries with tenacity, the limiter.

Every request names the project in its User-Agent and carries no contact address. A retryable
answer (a dropped connection, 429, 5xx, and for the NVD a 403, which is how it answers a client over
its limit) is retried with exponential backoff that honours Retry-After. Any other refusal raises
Refused with the status, so a source that declines a client is recorded as a refusal, never retried
into a ban and never swallowed. Downloads stream to disk, decoded from any transfer encoding, and are
hashed as they arrive, so the digest is the digest of the file as published, a large file is never
held in memory and never read twice.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from tenacity import RetryCallState, Retrying, retry_if_exception_type, stop_after_attempt

from unscheduled_sources.limiter import RateLimiter
from unscheduled_sources.timeutil import utcnow

USER_AGENT = "unscheduled/0.1 (+https://github.com/mekala27-45/unscheduled)"
DEFAULT_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})


class FetchError(RuntimeError):
    """A source could not be read."""


class Refused(FetchError):
    """The publisher answered with a refusal that retrying will not change."""

    def __init__(self, url: str, status: int, excerpt: str) -> None:
        super().__init__(f"{url} refused the request with HTTP {status}: {excerpt[:200]}")
        self.url = url
        self.status = status
        self.excerpt = excerpt[:500]


class Retryable(FetchError):
    def __init__(self, url: str, status: int, retry_after: float | None) -> None:
        super().__init__(f"{url} answered HTTP {status}, retrying")
        self.status = status
        self.retry_after = retry_after


@dataclass(frozen=True)
class Response:
    url: str
    status: int
    headers: Mapping[str, str]
    content: bytes
    fetched_at: datetime
    elapsed_s: float

    def json(self) -> Any:
        import json

        return json.loads(self.content)


@dataclass(frozen=True)
class Downloaded:
    url: str
    path: Path
    sha256: str
    size: int
    fetched_at: datetime
    headers: Mapping[str, str] = field(default_factory=dict)


def full_url(url: str, params: Mapping[str, Any] | None) -> str:
    """The URL with its query, as the lock records it. Credentials travel in headers, never here."""
    if not params:
        return url
    return str(httpx.URL(url, params={k: str(v) for k, v in params.items()}))


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("retry-after")
    if value is None:
        return None
    try:
        return max(float(value), 0.0)
    except ValueError:
        return None


class Http:
    def __init__(
        self,
        *,
        limiter: RateLimiter | None = None,
        retry_statuses: frozenset[int] = DEFAULT_RETRY_STATUSES,
        attempts: int = 6,
        backoff_s: float = 2.0,
        max_backoff_s: float = 120.0,
        timeout_s: float = 300.0,
        headers: Mapping[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        base = {"User-Agent": USER_AGENT}
        base.update(headers or {})
        self.limiter = limiter
        self.retry_statuses = retry_statuses
        self.attempts = attempts
        self.backoff_s = backoff_s
        self.max_backoff_s = max_backoff_s
        self._sleep = sleep
        self.client = httpx.Client(
            headers=base,
            timeout=httpx.Timeout(timeout_s, connect=60.0),
            follow_redirects=True,
            transport=transport,
            trust_env=True,
        )

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> Http:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _wait(self, state: RetryCallState) -> float:
        error = state.outcome.exception() if state.outcome is not None else None
        exponential = min(self.backoff_s * (2 ** (state.attempt_number - 1)), self.max_backoff_s)
        if isinstance(error, Retryable) and error.retry_after is not None:
            return min(max(error.retry_after, exponential), self.max_backoff_s * 5)
        return exponential

    def _retrying(self) -> Retrying:
        return Retrying(
            stop=stop_after_attempt(self.attempts),
            wait=self._wait,
            retry=retry_if_exception_type((Retryable, httpx.TransportError)),
            sleep=self._sleep,
            reraise=True,
        )

    def _check(self, url: str, response: httpx.Response, body: bytes | None) -> None:
        if response.status_code < 400:
            return
        if response.status_code in self.retry_statuses:
            raise Retryable(url, response.status_code, _retry_after(response))
        excerpt = (body or b"").decode("utf-8", "replace")
        raise Refused(url, response.status_code, excerpt)

    def get(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        recorded = full_url(url, params)

        def attempt() -> Response:
            if self.limiter is not None:
                self.limiter.acquire()
            started = time.monotonic()
            fetched_at = utcnow()
            response = self.client.get(url, params=params, headers=headers)
            body = response.content
            self._check(recorded, response, body)
            return Response(
                url=recorded,
                status=response.status_code,
                headers=dict(response.headers),
                content=body,
                fetched_at=fetched_at,
                elapsed_s=time.monotonic() - started,
            )

        result: Response = self._retrying()(attempt)
        return result

    def download(
        self,
        url: str,
        dest: Path,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Downloaded:
        recorded = full_url(url, params)
        dest.parent.mkdir(parents=True, exist_ok=True)
        partial = dest.with_name(dest.name + ".part")

        def attempt() -> Downloaded:
            if self.limiter is not None:
                self.limiter.acquire()
            fetched_at = utcnow()
            digest = hashlib.sha256()
            size = 0
            with self.client.stream("GET", url, params=params, headers=headers) as response:
                if response.status_code >= 400:
                    body = response.read()
                    self._check(recorded, response, body)
                with partial.open("wb") as handle:
                    for chunk in response.iter_bytes(1 << 20):
                        digest.update(chunk)
                        size += len(chunk)
                        handle.write(chunk)
                kept = {k: v for k, v in response.headers.items() if k.lower() in _KEPT_HEADERS}
            partial.replace(dest)
            return Downloaded(recorded, dest, digest.hexdigest(), size, fetched_at, kept)

        result: Downloaded = self._retrying()(attempt)
        return result


_KEPT_HEADERS = {"last-modified", "etag", "content-length", "content-type", "x-goog-generation"}
