"""The bronze contract is exact, upserts are inert on a rerun, and compaction changes nothing twice."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import polars as pl
import pytest
from unscheduled_sources.bronze import Bronze, file_digest
from unscheduled_sources.contract import TABLES, ContractError, conform, frame

T1 = datetime(2026, 11, 8, 0, 0, tzinfo=UTC)
T2 = datetime(2026, 11, 8, 2, 0, tzinfo=UTC)


def _records(snapshot: datetime, digests: list[str]) -> pl.DataFrame:
    return frame(
        "cve_records",
        [
            {
                "cve_id": f"CVE-202{i % 2 + 4}-{1000 + i}",
                "state": "PUBLISHED",
                "problem_cwes": ["CWE-79"],
                "has_affected_versions": True,
                "references_count": 2,
                "adp_cisa_present": False,
                "snapshot_at": snapshot,
                "record_digest": d,
            }
            for i, d in enumerate(digests)
        ],
    )


def _digests(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): file_digest(p) for p in sorted(root.rglob("*.parquet"))}


def test_every_contract_table_round_trips_through_parquet(tmp_path: Path) -> None:
    for name, spec in TABLES.items():
        df = pl.DataFrame(schema=spec.schema)
        df.write_parquet(tmp_path / f"{name}.parquet")
        back = pl.read_parquet(tmp_path / f"{name}.parquet")
        assert dict(back.schema) == dict(spec.schema), name


def test_a_retyped_column_breaks_the_contract() -> None:
    df = _records(T1, ["a"]).with_columns(pl.col("references_count").cast(pl.Int64))
    with pytest.raises(ContractError, match="references_count"):
        conform("cve_records", df)


def test_a_missing_or_extra_column_breaks_the_contract() -> None:
    df = _records(T1, ["a"])
    with pytest.raises(ContractError, match="missing"):
        conform("cve_records", df.drop("record_digest"))
    with pytest.raises(ContractError, match="outside the contract"):
        conform("cve_records", df.with_columns(pl.lit(1).alias("extra")))
    with pytest.raises(ContractError, match="outside the contract"):
        frame("kev", [{"cve_id": "CVE-2021-44228", "catalog_version": "1", "invented": True}])


def test_an_upsert_written_twice_writes_nothing_the_second_time(tmp_path: Path) -> None:
    bronze = Bronze(tmp_path)
    first = bronze.write("cve_records", _records(T1, ["a", "b", "c"]), "batch-1")
    assert first.rows_in == 3 and first.rows_changed == 3
    before = _digests(tmp_path)
    again = Bronze(tmp_path).write("cve_records", _records(T1, ["a", "b", "c"]), "batch-1")
    assert again.rows_changed == 0 and again.files == ()
    assert _digests(tmp_path) == before


def test_the_first_snapshot_of_a_record_is_kept(tmp_path: Path) -> None:
    bronze = Bronze(tmp_path)
    bronze.write("cve_records", _records(T1, ["a", "b"]), "baseline")
    later = bronze.write("cve_records", _records(T2, ["a", "x"]), "delta")
    assert later.rows_changed == 1
    table = bronze.read("cve_records")
    assert table.height == 3
    kept = table.filter(pl.col("record_digest") == "a")
    assert kept.get_column("snapshot_at").to_list() == [T1]


def test_records_land_in_the_partition_of_their_year(tmp_path: Path) -> None:
    Bronze(tmp_path).write("cve_records", _records(T1, ["a", "b"]), "b1")
    years = sorted(p.parent.name for p in tmp_path.rglob("*.parquet"))
    assert years == ["year=2024", "year=2025"]


def test_compaction_is_idempotent_and_keeps_every_key(tmp_path: Path) -> None:
    bronze = Bronze(tmp_path)
    bronze.write("cve_records", _records(T1, ["a", "b"]), "b1")
    bronze.write("cve_records", _records(T2, ["c", "d"]), "b2")
    bronze.compact("cve_records")
    once = _digests(tmp_path)
    assert all(Path(p).name.startswith("part-") for p in once)
    bronze.compact("cve_records")
    assert _digests(tmp_path) == once
    assert bronze.read("cve_records").height == 4


def test_a_replace_table_is_rewritten_whole_and_counts_its_changes(tmp_path: Path) -> None:
    bronze = Bronze(tmp_path)
    rows = [{"cwe_id": "CWE-79", "name": "XSS", "abstraction": "Base", "parents": ["CWE-74"]}]
    first = bronze.write("cwe", frame("cwe", rows), "cwe")
    assert first.rows_changed == 1
    same = bronze.write("cwe", frame("cwe", rows), "cwe")
    assert same.rows_changed == 0
    rows.append({"cwe_id": "CWE-16", "name": "Configuration", "abstraction": "Category", "parents": []})
    grown = bronze.write("cwe", frame("cwe", rows), "cwe")
    assert grown.rows_changed == 1
    assert bronze.read("cwe").height == 2
