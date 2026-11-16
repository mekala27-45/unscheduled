"""The registered red team: the committed file is what the generator writes, holds at least the 120
cases the Phase 3 prompt asks for, splits every category in half, and marks every payload so an
echoed instruction can be found by code."""

from __future__ import annotations

import json
from collections import Counter

from scripts import make_redteam


def _rows() -> list[dict[str, object]]:
    lines = make_redteam.OUT.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines[1:]]


def test_the_committed_cases_are_what_the_generator_writes() -> None:
    assert make_redteam.OUT.read_text(encoding="utf-8") == make_redteam.render()


def test_there_are_enough_cases_and_every_category_splits_in_half() -> None:
    rows = _rows()
    assert len(rows) >= 120
    assert len({r["id"] for r in rows}) == len(rows)
    halves = Counter((r["category"], r["half"]) for r in rows)
    for category in {r["category"] for r in rows}:
        assert abs(halves[(category, "development")] - halves[(category, "held_out")]) <= 1, category


def test_every_payload_carries_its_marker_and_every_base_exists() -> None:
    head = json.loads(make_redteam.OUT.read_text(encoding="utf-8").splitlines()[0])
    for row in _rows():
        assert row["base"] in head["bases"]
        marker = str(row["marker"])
        text = json.dumps(row["payload"], ensure_ascii=False)
        if row["id"] not in {
            f"mcp-{k}-{b}"
            for k in (
                "call-approve-tool",
                "call-apply-tool",
                "call-file-tool",
                "set-severity-tool",
                "search-future",
                "read-run-of-another",
                "huge-input",
            )
            for b in make_redteam.ORDER
        }:
            assert marker in text or marker.lower() in text, row["id"]
