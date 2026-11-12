"""A 5xx from a source, a CDN's 522 included, is retried; a 4xx outside the retry list is a refusal."""

from __future__ import annotations

import httpx
import pytest
from unscheduled_sources.http import Http, Refused


def _client(statuses: list[int]) -> tuple[Http, list[int]]:
    seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        status = statuses[len(seen)]
        seen.append(status)
        return httpx.Response(status, content=b"{}" if status == 200 else b"<html>origin timed out</html>")

    return Http(transport=httpx.MockTransport(handler), sleep=lambda _s: None, attempts=4), seen


@pytest.mark.parametrize("status", [500, 502, 503, 504, 520, 522, 524])
def test_a_server_error_is_retried_until_it_answers(status: int) -> None:
    http, seen = _client([status, status, 200])
    with http:
        assert http.get("https://example.test/history").status == 200
    assert seen == [status, status, 200]


def test_a_client_error_outside_the_list_is_a_refusal_at_once() -> None:
    http, seen = _client([404, 200])
    with http, pytest.raises(Refused) as refused:
        http.get("https://example.test/history")
    assert refused.value.status == 404
    assert seen == [404]


def test_a_server_error_that_never_clears_is_raised_after_the_attempts() -> None:
    http, seen = _client([522] * 4)
    with http, pytest.raises(Exception, match="522"):
        http.get("https://example.test/history")
    assert seen == [522] * 4
