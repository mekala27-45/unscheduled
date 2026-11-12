"""The serving bundle carries every stand in and every finding of the committed exposure, once."""

from __future__ import annotations

import json
from pathlib import Path

from scripts import build_serving_bundle as bundle

ROOT = Path(__file__).resolve().parents[2]


def test_every_stand_in_is_a_product_with_its_pin() -> None:
    products = bundle.product_frame(ROOT)
    assert products.height == 6
    assert products.get_column("product_id").n_unique() == 6
    assert products.filter(products["commit"].is_null()).height == 0
    assert set(products.get_column("kind")) == {"repository", "image"}


def test_every_finding_of_the_exposure_is_served_once() -> None:
    findings = bundle.finding_frame(ROOT)
    summary = json.loads((ROOT / "results" / "exposure" / "summary.json").read_text(encoding="utf-8"))
    expected = sum(
        p[snapshot]["findings"] for p in summary["products"].values() for snapshot in ("pin", "today")
    )
    assert findings.height == expected
    assert findings.get_column("finding_id").n_unique() == findings.height
    assert set(findings.get_column("snapshot")) == {"pin", "today"}
    assert findings.filter(findings["as_of"].is_null()).height == 0


def test_the_locks_are_summarized_by_source_without_any_secret() -> None:
    locks = bundle.locks_summary(ROOT)
    assert "nvd" in locks and "kev" in locks
    assert all(len(v["lock_sha256"]) == 64 for v in locks.values())
    text = json.dumps(locks)
    assert "postgres" not in text and "token" not in text.lower()
