"""The config tables the lake reads: the filer groups from config/filers.yaml as the fetcher writes it."""

from __future__ import annotations

from pathlib import Path

from unscheduled_lake.config_tables import filer_types

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
