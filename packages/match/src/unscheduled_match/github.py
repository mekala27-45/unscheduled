"""The GitHub reads the product rule needs, unauthenticated, inside GitHub's published rate limits.

No token is ever sent. Unauthenticated, the search API allows 10 requests a minute and the core API
60 an hour (GitHub REST documentation, read 7 November 2026). The client paces search calls by the
limit the response headers report, waits for the reset when a window is spent, and honours
Retry-After. Files at a commit are read from raw.githubusercontent.com, which is not the API.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
USER_AGENT = "unscheduled-build (+https://github.com/mekala27-45/unscheduled)"


class RateLimited(RuntimeError):
    """The API refused after waiting out its window more than once."""


class GitHub:
    def __init__(
        self,
        client: httpx.Client,
        *,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
        max_waits: int = 4,
    ) -> None:
        self.client = client
        self.sleep = sleep
        self.clock = clock
        self.max_waits = max_waits
        self._next_search = 0.0
        self.calls: dict[str, int] = {"search": 0, "raw": 0}

    def _headers(self) -> dict[str, str]:
        return {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}

    def _pace(self, response: httpx.Response) -> None:
        limit = int(response.headers.get("x-ratelimit-limit", "10") or 10)
        remaining = int(response.headers.get("x-ratelimit-remaining", "1") or 1)
        reset = float(response.headers.get("x-ratelimit-reset", "0") or 0)
        now = self.clock()
        spacing = 60.0 / max(limit, 1)
        self._next_search = now + spacing
        if remaining <= 0 and reset > now:
            self._next_search = reset + 1.0

    def search(self, kind: str, params: dict[str, str | int]) -> dict[str, Any]:
        """One search API call (repositories or commits), waiting as the limits require."""
        for _ in range(self.max_waits + 1):
            wait = self._next_search - self.clock()
            if wait > 0:
                self.sleep(wait)
            response = self.client.get(f"{API}/search/{kind}", params=params, headers=self._headers())
            self.calls["search"] += 1
            self._pace(response)
            if response.status_code in (403, 429):
                retry_after = response.headers.get("retry-after")
                if retry_after:
                    self._next_search = self.clock() + float(retry_after)
                elif self._next_search <= self.clock():
                    self._next_search = self.clock() + 60.0
                continue
            response.raise_for_status()
            data: dict[str, Any] = response.json()
            return data
        raise RateLimited(f"search/{kind} refused after {self.max_waits} waits")

    def repositories(self, query: str, page: int = 1, per_page: int = 100) -> list[dict[str, Any]]:
        data = self.search(
            "repositories", {"q": query, "sort": "stars", "order": "desc", "per_page": per_page, "page": page}
        )
        items: list[dict[str, Any]] = data.get("items", [])
        return items

    def commits_before(self, repo: str, cutoff_date: str, per_page: int = 5) -> list[dict[str, Any]]:
        """Commits on the default branch committed before the cutoff date, newest first."""
        data = self.search(
            "commits",
            {
                "q": f"repo:{repo} committer-date:<{cutoff_date}",
                "sort": "committer-date",
                "order": "desc",
                "per_page": per_page,
            },
        )
        items: list[dict[str, Any]] = data.get("items", [])
        return items

    def raw(self, repo: str, ref: str, path: str) -> bytes | None:
        """A file at a commit or branch, or None when it is not there."""
        response = self.client.get(f"{RAW}/{repo}/{ref}/{path}", headers={"User-Agent": USER_AGENT})
        self.calls["raw"] += 1
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.content

    def raw_exists(self, repo: str, ref: str, path: str) -> bool:
        response = self.client.head(f"{RAW}/{repo}/{ref}/{path}", headers={"User-Agent": USER_AGENT})
        self.calls["raw"] += 1
        if response.status_code == 404:
            return False
        response.raise_for_status()
        return True
