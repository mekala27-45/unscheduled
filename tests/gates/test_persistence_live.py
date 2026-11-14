"""The live persistence check sends its two lookups over one connection, so they come from one client."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from scripts import check_persistence as cp


def test_both_lookups_go_over_one_client(monkeypatch: pytest.MonkeyPatch) -> None:
    # Each client stands for one address leaving a proxy: its own budget, counted down per request.
    made: list[httpx.Client] = []
    real = httpx.Client

    def client(**kwargs: Any) -> httpx.Client:
        remaining = iter(range(1999, 0, -1))

        def answer(request: httpx.Request) -> httpx.Response:
            headers = {"X-Budget-Remaining": str(next(remaining)), "X-Data-Version": "serving-1+abc"}
            return httpx.Response(200, json={"items": []}, headers=headers)

        made.append(real(transport=httpx.MockTransport(answer), **kwargs))
        return made[-1]

    monkeypatch.setattr(cp, "wait_for", lambda base, seconds: None)
    monkeypatch.setattr(cp.httpx, "Client", client)
    record = cp.check_live("https://api.example.test")
    assert len(made) == 1
    assert record["budget_remaining"] == ["1999", "1998"]
    assert record["passed"], record["problems"]
