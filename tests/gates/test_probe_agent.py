"""The Phase 3 probe: the pin rule picks the right release, and a provider probe never keeps a key.

The pin rule reads the PyPI release list: the newest release whose first file was uploaded on or
before the cutoff, skipping yanked releases and prereleases. A provider without its secret is
recorded as absent without a request; with one, the probe lists the models and sends one short line,
and nothing it writes carries the key or the answer text.
"""

from __future__ import annotations

import json
from datetime import date

import httpx

from scripts.probe_hosts import pinned_release, probe_provider

CUTOFF = date(2026, 11, 2)


def _files(day: str, yanked: bool = False) -> list[dict[str, object]]:
    return [{"upload_time_iso_8601": f"{day}T12:00:00.000000Z", "yanked": yanked}]


def test_the_pin_is_the_newest_release_at_least_the_cutoff_old() -> None:
    body = {
        "info": {"version": "1.3.0", "requires_python": ">=3.10"},
        "releases": {
            "1.1.0": _files("2026-09-01"),
            "1.2.0": _files("2026-10-20"),
            "1.2.1": _files("2026-10-30", yanked=True),
            "1.2.2rc1": _files("2026-11-01"),
            "1.1.9": _files("2026-11-01"),
            "1.3.0": _files("2026-11-14"),
        },
    }
    picked = pinned_release(body, CUTOFF)
    assert picked["latest"] == "1.3.0" and picked["latest_released"] == "2026-11-14"
    assert picked["pin"] == "1.2.0" and picked["pin_released"] == "2026-10-20"


def test_a_library_with_nothing_old_enough_has_no_pin() -> None:
    body = {"info": {"version": "0.1.0"}, "releases": {"0.1.0": _files("2026-11-10")}}
    assert pinned_release(body, CUTOFF)["pin"] is None


COMMON = {"probe_prompt": "Reply with the single word ready.", "probe_max_tokens": 5}
CFG = {
    "base_url": "https://api.example.test/openai/v1",
    "key_env": "EXAMPLE_API_KEY",
    "models": ["big-model", "missing-model"],
}


def test_a_provider_without_its_secret_is_absent_and_not_called() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"no request without a key: {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(refuse))
    out = probe_provider(client, "example", CFG, COMMON, None)
    assert out["token_present"] is False and out["ok"] is True
    assert "EXAMPLE_API_KEY is not set" in out["note"]


def test_a_provider_answer_keeps_the_limits_and_never_the_key_or_the_text() -> None:
    key = "sk-test-0123456789abcdefghijklmnop"
    seen: list[str] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["authorization"])
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "big-model"}, {"id": "other"}]})
        sent = json.loads(request.content)
        assert sent["model"] == "big-model" and sent["max_tokens"] == 5
        return httpx.Response(
            200,
            headers={"x-ratelimit-limit-requests": "1000", "x-ratelimit-remaining-tokens": "7990"},
            json={
                "choices": [{"message": {"content": "ready, and a secret phrase"}}],
                "usage": {"prompt_tokens": 9, "completion_tokens": 1, "total_tokens": 10},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(answer))
    out = probe_provider(client, "example", CFG, COMMON, key)
    assert seen == [f"Bearer {key}", f"Bearer {key}"]
    assert out["wanted"] == {"big-model": True, "missing-model": False}
    assert out["one_line"]["limits"] == {
        "x-ratelimit-limit-requests": "1000",
        "x-ratelimit-remaining-tokens": "7990",
    }
    assert out["one_line"]["usage"]["total_tokens"] == 10
    written = json.dumps(out)
    assert key not in written and "secret phrase" not in written
