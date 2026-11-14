"""The training sets are point in time: nothing known after day 0 reaches an input column."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import duckdb
import polars as pl
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from unscheduled_models import sets

from scripts import check_test_labels

PLANT = "PLANTED"
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _lake(published: datetime, plant_after_s: int) -> duckdb.DuckDBPyConnection:
    """A lake of one CVE published at `published`, with honest day 0 facts and planted facts that
    become known `plant_after_s` seconds after day 0 ends."""
    con = duckdb.connect()
    con.execute("set TimeZone = 'UTC'")
    for schema in ("gold", "silver", "config"):
        con.execute(f"create schema {schema}")
    t0 = datetime(published.year, published.month, published.day, tzinfo=UTC) + timedelta(days=1)
    late = t0 + timedelta(seconds=plant_after_s)
    con.execute(
        """create table gold.cve_current as select
            'CVE-2025-0001' as cve_id, ?::timestamptz as published, 'test' as split_window, 'acme' as filer,
            'vendor' as filer_type, ?::timestamptz as date_reserved, 'the current text PLANTED' as description,
            'Critical' as nvd_cvss31_band, ? as nvd_cvss31_vector, ['CWE-79'] as nvd_cwes,
            cast(?::timestamptz as date) as kev_date_added, 'PUBLISHED' as state""",
        [published, published - timedelta(days=3), VECTOR, late],
    )
    con.execute(
        "create table silver.cve_fact (cve_id varchar, field varchar, source varchar, value varchar, "
        "known_from timestamptz, known_to timestamptz)"
    )
    facts = [
        ("cvss31_vector", "acme", VECTOR, published, late),
        ("cvss31_vector", "acme", f"{PLANT}-vector", late, None),
        ("cvss31_severity", "acme", "HIGH", published, None),
        ("cvss31_severity", "CISA-ADP", f"{PLANT}-band", late, None),
        ("ssvc_exploitation", "CISA-ADP", f"{PLANT}-ssvc", late, None),
        ("cwe", "acme", "CWE-79", published, None),
        ("cwe", "acme", f"{PLANT}-cwe", late, None),
        ("exploit_code", "metasploit", "module", late, None),
        ("cvss31_vector", "acme", f"{PLANT}-superseded", published - timedelta(days=2), published),
    ]
    con.executemany(
        "insert into silver.cve_fact values ('CVE-2025-0001', ?, ?, ?, ?, ?)",
        [list(f) for f in facts],
    )
    con.execute(
        "create table config.lake_build as select ?::timestamptz as data_cut", [late + timedelta(days=400)]
    )
    details = json.dumps([{"action": "Added", "type": "Description", "newValue": "the day 0 text"}])
    edit = json.dumps([{"action": "Changed", "type": "Description", "newValue": f"{PLANT} description"}])
    con.execute(
        "create temp table nvd_changes_bronze as select * from (values "
        "('CVE-2025-0001', 'New CVE Received', 'a', ?::timestamptz, ?), "
        "('CVE-2025-0001', 'CVE Modified', 'b', ?::timestamptz, ?)) "
        "t(cve_id, event_name, cve_change_id, created, details_json)",
        [published, details, late, edit],
    )
    affected = json.dumps([{"vendor": "acme", "product": "door controller"}])
    con.execute(
        "create temp table cve_records_bronze as select 'CVE-2025-0001' as cve_id, ? as affected_json, "
        "true as has_affected_versions, ?::timestamptz as snapshot_at, 'd' as record_digest",
        [affected, late],
    )
    return con


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    second_of_day=st.integers(min_value=0, max_value=86_399),
    plant_after_s=st.integers(min_value=1, max_value=10_000_000),
)
def test_no_fact_known_after_day_0_reaches_an_input(second_of_day: int, plant_after_s: int) -> None:
    published = datetime(2025, 6, 3, tzinfo=UTC) + timedelta(seconds=second_of_day)
    frame = sets.build_frame(_lake(published, plant_after_s))
    row = frame.select(sets.INPUT_COLUMNS).to_dicts()[0]
    assert not any(PLANT in str(value) for value in row.values()), row
    assert row["filer_cvss31_vector"] == VECTOR
    assert row["filer_band"] == "HIGH"
    assert row["description"] == "the day 0 text" and row["description_rule"] == "history"
    assert row["filer_cwes"] == ["CWE-79"]
    assert row["exploit_code_by_day0"] is False
    assert row["adp_band"] is None and row["adp_ssvc_exploitation"] is None
    labels = frame.select(sets.LABEL_COLUMNS).to_dicts()[0]
    assert labels["band"] == "CRITICAL" and labels["nvd_AV"] == "N"


def test_a_fact_known_at_the_end_of_day_0_counts(tmp_path: Path) -> None:
    published = datetime(2025, 6, 3, 23, 0, tzinfo=UTC)
    con = _lake(published, 10)
    con.execute(
        "insert into silver.cve_fact values ('CVE-2025-0001', 'ssvc_exploitation', 'CISA-ADP', 'poc', ?, null)",
        [datetime(2025, 6, 4, tzinfo=UTC)],
    )
    row = sets.build_frame(con).to_dicts()[0]
    assert row["adp_ssvc_exploitation"] == "poc"


def test_the_kev_label_and_its_censoring() -> None:
    published = datetime(2025, 6, 3, 12, 0, tzinfo=UTC)
    row = sets.build_frame(_lake(published, 3600)).to_dicts()[0]
    assert row["kev_180"] is True and row["kev_event"] is True and row["days_to_kev"] == 1
    assert row["kev_q03"] is False


def test_the_test_labels_are_sealed(tmp_path: Path) -> None:
    pl.DataFrame({"cve_id": ["CVE-2025-0001"]}).write_parquet(tmp_path / sets.labels_name("test"))
    with pytest.raises(PermissionError):
        sets.load_labels(tmp_path, "test")
    assert sets.load_labels(tmp_path, "test", unsealed=True).height == 1


def test_the_test_product_labels_are_sealed(tmp_path: Path) -> None:
    pl.DataFrame({"cve_id": ["CVE-2025-0001"]}).write_parquet(tmp_path / sets.product_labels_name("test"))
    with pytest.raises(PermissionError):
        sets.load_product_labels(tmp_path, "test")
    assert sets.load_product_labels(tmp_path, "test", unsealed=True).height == 1


QUALCOMM = (
    "AND\n     OR\n          *cpe:2.3:o:qualcomm:snapdragon_8\\+_gen_1_firmware:-:*:*:*:*:*:*:*\n"
    "     OR\n          cpe:2.3:h:qualcomm:snapdragon_8\\+_gen_1:-:*:*:*:*:*:*:*"
)
ADOBE = "OR\n     *cpe:2.3:a:adobe:indesign:*:*:*:*:*:*:*:* versions up to (including) 18.5.4"


def test_only_vulnerable_matches_are_labels_and_quoting_is_kept() -> None:
    pairs, matches = sets.configuration_pairs([QUALCOMM, ADOBE])
    assert pairs == ["adobe:indesign", "qualcomm:snapdragon_8\\+_gen_1_firmware"]
    assert matches == 3


def test_configuration_events_rebuild_the_state_at_the_cut() -> None:
    nodes: Counter[str] = Counter()
    sets.apply_configuration_events(
        [
            {"type": "CPE Configuration", "action": "Added", "newValue": ADOBE},
            {"type": "CPE Configuration", "action": "Added", "newValue": QUALCOMM},
            {"type": "Description", "action": "Added", "newValue": "not a configuration"},
        ],
        nodes,
    )
    changed = ADOBE.replace("18.5.4", "18.5.5")
    sets.apply_configuration_events(
        [
            {"type": "CPE Configuration", "action": "Changed", "oldValue": ADOBE, "newValue": changed},
            {"type": "CPE Configuration", "action": "Removed", "oldValue": QUALCOMM},
            {"type": "CPE Configuration", "action": "Removed", "oldValue": "a node never added"},
        ],
        nodes,
    )
    live = [node for node, n in nodes.items() if n > 0]
    assert live == [changed]
    assert sets.configuration_pairs(live) == (["adobe:indesign"], 1)


def test_an_input_column_empty_for_a_whole_window_is_named() -> None:
    frame = pl.DataFrame(
        {c: [None] for c in sets.INPUT_COLUMNS}, schema={c: pl.String for c in sets.INPUT_COLUMNS}
    ).with_columns(
        pl.lit("train").alias("split"), pl.lit("CVE-1").alias("cve_id"), pl.lit("text").alias("description")
    )
    problems = sets.empty_columns(frame)
    assert "train: filer" in problems and "development: no rows" in problems
    assert not any(p.endswith(": description") for p in problems)


def test_joined_text_carries_what_the_floor_gets() -> None:
    text = sets.joined_text("a flaw", "acme", "acme door", VECTOR, "HIGH", "poc")
    assert text.splitlines() == [
        "a flaw",
        "Filer: acme",
        "Products: acme door",
        f"Filer score: {VECTOR}",
        "CISA ADP severity: HIGH",
        "CISA SSVC exploitation: poc",
    ]
    assert sets.joined_text(None, None, None) == ""


def _module(root: Path, where: str, text: str) -> Path:
    path = root / where
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_the_test_label_gate_passes_the_scorer_and_the_builder(tmp_path: Path) -> None:
    files = [
        _module(tmp_path, "scripts/score_test.py", "load_labels(folder, 'test', unsealed=True)\n"),
        _module(
            tmp_path,
            "packages/models/src/unscheduled_models/sets.py",
            "TEST_LABELS = 'test_labels.parquet'\n",
        ),
        _module(
            tmp_path, "packages/models/src/unscheduled_models/floors.py", "load_labels(folder, 'train')\n"
        ),
    ]
    assert check_test_labels.check(tmp_path, files) == 3


def test_the_test_label_gate_catches_another_reader(tmp_path: Path) -> None:
    for text in (
        "x = 'test_labels.parquet'\n",
        "from sets import TEST_LABELS\n",
        "load_labels(f, 'test', unsealed=True)\n",
        "x = 'test_product_labels.parquet'\n",
        "from sets import TEST_PRODUCT_LABELS\n",
    ):
        path = _module(tmp_path, "packages/models/src/unscheduled_models/floors.py", text)
        with pytest.raises(ValueError, match="test label gate failed"):
            check_test_labels.check(tmp_path, [path])


def test_the_test_label_gate_refuses_nothing(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no files"):
        check_test_labels.check(tmp_path, [])
