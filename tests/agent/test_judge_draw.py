"""The forty drafts for the judge: twenty from the floor and twenty from the models, drawn by seed,
shown without the configuration that wrote each, the key kept apart for the scorer."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from scripts import draw_judge_drafts as judge
from scripts.eval_agent import kept


def _rows() -> list[dict[str, Any]]:
    rows = []
    for configuration in ("floor", "groq/openai/gpt-oss-120b", "gemini/gemini-flash"):
        for i in range(30):
            for kind in ("plan", "warning"):
                rows.append(
                    {
                        "configuration": configuration,
                        "cve_id": f"CVE-2025-{1000 + i}",
                        "as_of": "2025-06-01T23:59:59.999999+00:00",
                        "kind": kind,
                        "sha256": f"{i:064x}",
                        "blocked": i == 3,
                        "draft": {
                            "kind": "patch_plan" if kind == "plan" else "early_warning",
                            "steps": [str(i)],
                        },
                    }
                )
    return rows


def test_twenty_from_each_half_none_blocked_and_the_same_every_time() -> None:
    chosen = judge.draw(_rows())
    assert len(chosen) == 40 and not any(r["blocked"] for r in chosen)
    assert sum(r["configuration"] == "floor" for r in chosen) == 20
    assert [judge.draft_id(r) for r in chosen] == [judge.draft_id(r) for r in judge.draw(_rows())]
    assert [judge.draft_id(r) for r in chosen] == sorted(judge.draft_id(r) for r in chosen)


def test_the_console_never_sees_the_configuration(tmp_path: Path) -> None:
    source = tmp_path / "drafts.jsonl.gz"
    source.write_bytes(gzip.compress("".join(json.dumps(r) + "\n" for r in _rows()).encode()))
    assert judge.main(["--drafts", str(source), "--out", str(tmp_path)]) == 0
    shown = (tmp_path / "judge" / "drafts.json").read_text(encoding="utf-8")
    assert "configuration" not in shown and "groq" not in shown and "floor" not in shown
    key = json.loads((tmp_path / "judge_key.json").read_text(encoding="utf-8"))
    ids = [d["draft_id"] for d in json.loads(shown)["drafts"]]
    assert sorted(key["configuration"]) == sorted(ids) and len(set(ids)) == 40


def test_too_few_model_drafts_are_refused() -> None:
    floor_only = [r for r in _rows() if r["configuration"] == "floor"]
    with pytest.raises(ValueError, match="recorded calls"):
        judge.draw(floor_only)


def test_a_run_keeps_each_verified_draft_with_its_hash() -> None:
    at = datetime(2025, 6, 1, 23, 59, 59, tzinfo=UTC)
    state = {
        "plan_check": {"sha256": "a" * 64, "blocked": False, "draft": {"kind": "patch_plan"}},
        "warning_check": None,
    }
    found = kept("floor", "CVE-2025-1", at, state)
    assert found == [
        {
            "configuration": "floor",
            "cve_id": "CVE-2025-1",
            "as_of": at.isoformat(),
            "kind": "plan",
            "sha256": "a" * 64,
            "blocked": False,
            "draft": {"kind": "patch_plan"},
        }
    ]
