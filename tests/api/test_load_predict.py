"""The load test's predict scenario: every call is a POST of one of the fixed bodies, a run passes only
when every call answers 200, and the manifest part carries the predict latencies only when some ran."""

from __future__ import annotations

import json
from typing import Any

import httpx

from scripts import load_test


def transport(status_for: dict[int, int] | None = None) -> tuple[httpx.MockTransport, list[dict[str, Any]]]:
    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/v1/predict"
        body = json.loads(request.content)
        seen.append(body)
        status = (status_for or {}).get(len(seen), 200)
        return httpx.Response(status, json={"values": []})

    return httpx.MockTransport(handler), seen


def test_every_call_posts_a_fixed_body_and_all_must_answer() -> None:
    mock, seen = transport()
    result = load_test.predict("https://api.example", 9, 3, transport=mock)
    assert result["result"] == "pass"
    assert result["requests"] == 9 and result["ok"] == 9
    assert result["statuses"] == {"200": 9}
    assert {b["description"] for b in seen} == {b["description"] for b in load_test.PREDICT_BODIES}
    assert result["ms"]["p50"] is not None


def test_one_refused_call_fails_the_scenario() -> None:
    mock, _ = transport({2: 503})
    result = load_test.predict("https://api.example", 4, 1, transport=mock)
    assert result["result"] == "fail"
    assert result["statuses"] == {"200": 3, "503": 1}


def test_the_part_carries_the_predict_latencies_only_when_they_ran() -> None:
    record: dict[str, Any] = {
        "finished_at": "2026-11-14T12:00:00Z",
        "base_url": "https://api.example",
        "cold": {"idle_minutes_before": 0.0, "health": {"ms": 300.0}, "first_lookup": {"ms": 420.0}},
        "warm": {"ok": 10, "workers": 2, "ms": {"p50": 80.0, "p95": 120.0, "p99": 150.0}},
        "c8_lookup": {"verdict": "met", "p95_ms": 120.0, "threshold_p95_ms": 1500.0},
    }
    without = load_test.manifest_part(record)["values"]
    assert "load.predict_p50_ms" not in without
    record["predict"] = {"ok": 8, "ms": {"p50": 95.0, "p95": 140.0}}
    values = load_test.manifest_part(record)["values"]
    assert values["load.predict_requests"]["value"] == 8
    assert values["load.predict_p95_ms"]["value"] == 140.0


def test_the_fixed_bodies_are_requests_the_api_accepts() -> None:
    from unscheduled_api.schemas import PredictRequest

    for body in load_test.PREDICT_BODIES:
        PredictRequest.model_validate(body)
