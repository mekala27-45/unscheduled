"""The serving bundle carries every stand in and every finding of the committed exposure, once."""

from __future__ import annotations

import json
import shutil
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


def test_the_locks_are_summarized_by_source_without_any_secret(tmp_path: Path) -> None:
    # The locks ride in the lake release, not in git, so the test writes two the way the fetcher does.
    (tmp_path / "config").mkdir()
    shutil.copy(ROOT / "config" / "sources.yaml", tmp_path / "config" / "sources.yaml")
    locks_dir = tmp_path / "data" / "locks"
    locks_dir.mkdir(parents=True)
    for name, rows in (("nvd", [2000, 1500]), ("kev", [1484])):
        entries = [
            {"name": f"{name}-{i}", "rows": n, "sha256": "0" * 64, "size": 10, "url": "https://example.org/x"}
            for i, n in enumerate(rows)
        ]
        lock = {"lock_version": 1, "source": name, "updated_at": "2026-11-12T01:00:00Z", "entries": entries}
        (locks_dir / f"{name}.lock.json").write_text(json.dumps(lock), encoding="utf-8")
    locks = bundle.locks_summary(tmp_path)
    assert set(locks) == {"nvd", "kev"}
    assert locks["nvd"]["files"] == 2 and locks["nvd"]["rows"] == 3500 and locks["nvd"]["cadence"] == "daily"
    assert locks["kev"]["cadence"] == "hourly"
    assert all(len(v["lock_sha256"]) == 64 for v in locks.values())
    text = json.dumps(locks)
    assert "postgres" not in text and "token" not in text.lower()
