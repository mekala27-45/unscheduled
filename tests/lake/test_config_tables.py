"""The config tables the lake reads: the filer groups from config/filers.yaml as the fetcher writes it."""

from __future__ import annotations

from pathlib import Path

import polars as pl
from unscheduled_lake.config_tables import bronze_assigners, filer_types

ROOT = Path(__file__).resolve().parents[2]


def test_the_filer_groups_load_from_the_fetchers_mapping(tmp_path: Path) -> None:
    path = tmp_path / "filers.yaml"
    path.write_text(
        "filers:\n  2N:\n    group: vendor\n    cves: 5\n  1E:\n    group: other\n  nogroup:\n    cves: 1\n",
        encoding="utf-8",
    )
    frame = filer_types(path)
    assert frame.to_dicts() == [
        {"short_name": "1E", "org_id": None, "filer_type": "other"},
        {"short_name": "2N", "org_id": None, "filer_type": "vendor"},
    ]


def test_every_filer_in_the_committed_file_has_a_group() -> None:
    frame = filer_types(ROOT / "config" / "filers.yaml")
    assert frame.height > 500
    assert set(frame["filer_type"].unique()) <= {
        "MITRE",
        "national CERT",
        "research or bug bounty platform",
        "open source project",
        "vendor",
        "other",
    }


def test_an_assigner_the_file_does_not_hold_is_typed_by_the_rule(tmp_path: Path) -> None:
    # A first fetch from nothing wrote the file before the CVE List bronze existed, so it holds the
    # listed filers only; the lake types the other assigners the records name.
    path = tmp_path / "filers.yaml"
    path.write_text("filers:\n  Samsung:\n    group: vendor\n  mitre:\n    group: MITRE\n", encoding="utf-8")
    frame = filer_types(path, ["samsung", "Samsung", "@huntrdev", "JPCERT", None, ""])  # type: ignore[list-item]
    assert frame.to_dicts() == [
        {"short_name": "@huntrdev", "org_id": None, "filer_type": "other"},
        {"short_name": "JPCERT", "org_id": None, "filer_type": "national CERT"},
        {"short_name": "Samsung", "org_id": None, "filer_type": "vendor"},
        {"short_name": "mitre", "org_id": None, "filer_type": "MITRE"},
        {"short_name": "samsung", "org_id": None, "filer_type": "vendor"},
    ]


def test_the_assigners_are_read_from_the_cve_list_bronze(tmp_path: Path) -> None:
    assert bronze_assigners(tmp_path) == []
    part = tmp_path / "cve_records" / "year=2026"
    part.mkdir(parents=True)
    pl.DataFrame({"assigner_short_name": ["b", "a", None, "b"]}).write_parquet(part / "part-1.parquet")
    assert bronze_assigners(tmp_path) == ["a", "b"]
