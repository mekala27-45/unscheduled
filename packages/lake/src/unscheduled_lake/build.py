"""The lake build: bronze in, the lake file and its reports out, the same way every time.

    1. A fresh work database: one view per bronze table, the registered configuration as tables.
    2. The data cut, read from bronze (the newest time any source was seen), so the same bronze
       always gives the same cut, and with it the same censoring and the same windows.
    3. dbt build: staging, intermediate, silver, quarantine and gold, with every contract and test.
    4. The as-of checks on a sample of the real facts (parity with the macro, the planted fact).
    5. The lake file: silver, gold, quarantine and config copied out, its digest taken; a content
       digest per table, which two builds from the same bronze always share.
    6. The reports under results/lake/ and the manifest part results/parts/lake.json.

The build never edits bronze, and a rerun over the same bronze reproduces every content digest.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb
from unscheduled_core import paths
from unscheduled_core.manifest import ManifestBuilder

from unscheduled_lake import bronze, checks, config_tables, coverage, publish
from unscheduled_lake.db import one, rows, run
from unscheduled_lake.dbt_project import DbtPaths, default_paths, invoke, run_results
from unscheduled_lake.digest import table_digest
from unscheduled_lake.fields import HISTORY_START

# The newest observation time of each bronze table; the data cut is the newest of them.
CUT_COLUMNS: dict[str, str] = {
    "cve_records": "snapshot_at",
    "cve_metrics": "observed_at",
    "nvd_cves": "fetched_at",
    "nvd_changes": "created",
    "kev": "first_seen_commit",
    "vulnrichment": "last_modified",
    "exploit_signals": "first_seen",
}


@dataclass(frozen=True)
class Settings:
    root: Path
    bronze_root: Path
    lake_file: Path
    work_dir: Path
    results_dir: Path
    memory: str = "2GB"
    threads: int = 2
    keep_work: bool = False
    run_checks: bool = True
    check_cves: int = 200


def default_settings(**overrides: Any) -> Settings:
    root = paths.root()
    base: dict[str, Any] = {
        "root": root,
        "bronze_root": paths.bronze_dir(),
        "lake_file": paths.lake_file(),
        "work_dir": paths.data_dir() / "cache" / "lake",
        "results_dir": paths.results_dir(),
    }
    base.update(overrides)
    return Settings(**base)


def connect(path: Path, s: Settings, temp: Path) -> duckdb.DuckDBPyConnection:
    temp.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(path))
    run(con, f"set memory_limit = '{s.memory}'")
    run(con, f"set threads = {int(s.threads)}")
    run(con, f"set temp_directory = '{temp}'")
    run(con, "set TimeZone = 'UTC'")
    return con


def data_cut(con: duckdb.DuckDBPyConnection) -> datetime:
    parts = [f"select max({col}) as t from bronze.{table}" for table, col in CUT_COLUMNS.items()]
    row = one(con, f"select max(t) from ({' union all '.join(parts)})")
    if row[0] is None:
        raise RuntimeError("bronze holds no dated row; fetch the sources before building the lake")
    cut: datetime = row[0]
    return cut.astimezone(UTC)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8")


def locks_report(locks_dir: Path, data_cut: str) -> dict[str, Any]:
    """The locks the lake was built from: per source, the digest of its lock, its raw files and rows.

    The locks themselves ride in the lake release, not in git; this report is the committed record
    that every source was fetched and locked by digest when the lake was built.
    """
    sources: dict[str, Any] = {}
    for path in sorted(locks_dir.glob("*.lock.json")):
        lock = json.loads(path.read_text(encoding="utf-8"))
        entries = lock.get("entries") or []
        sources[path.name.removesuffix(".lock.json")] = {
            "lock_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "updated_at": lock.get("updated_at"),
            "raw_files": len(entries),
            "rows": sum(int(e.get("rows") or 0) for e in entries),
            "every_file_has_a_digest": all(len(str(e.get("sha256") or "")) == 64 for e in entries),
        }
    return {"data_cut": data_cut, "sources": sources}


def build(s: Settings) -> dict[str, Any]:
    started = time.monotonic()
    dbt_paths: DbtPaths = default_paths(s.work_dir)
    s.work_dir.mkdir(parents=True, exist_ok=True)
    for stale in (dbt_paths.work_db, dbt_paths.work_db.with_name(dbt_paths.work_db.name + ".wal")):
        stale.unlink(missing_ok=True)

    # The lake file is derived; the previous one goes before the build so two never share the disk.
    for old in (s.lake_file, s.lake_file.with_name(s.lake_file.name + ".wal")):
        old.unlink(missing_ok=True)
    con = connect(dbt_paths.work_db, s, dbt_paths.temp)
    tables = bronze.create_views(con, s.bronze_root)
    config_rows = config_tables.load(con, s.root)
    cut = data_cut(con)
    run(
        con,
        "create or replace table config.lake_build as select cast($cut as timestamptz) as data_cut",
        {"cut": cut},
    )
    history_data = coverage.data_history(con, HISTORY_START.date(), cut)
    con.close()
    history_ledger = coverage.ledger_history(s.root / "data" / "locks" / "ledger.jsonl")

    dbt_vars = {"data_cut": cut.isoformat()}
    # One dbt thread: DuckDB already uses every core inside a query, and a Python model holding the
    # interpreter would only stall a second dbt thread.
    os.environ["UNSCHED_DUCKDB_MEMORY"] = s.memory
    os.environ["UNSCHED_DUCKDB_THREADS"] = str(s.threads)
    os.environ["UNSCHED_DBT_THREADS"] = "1"
    (dbt_paths.target / "run_results.json").unlink(missing_ok=True)
    done = invoke(dbt_paths, ["build"], dbt_vars)
    if done.returncode < 0 or not (dbt_paths.target / "run_results.json").exists():
        raise RuntimeError(
            f"dbt build stopped before it finished (exit {done.returncode}): {(done.stdout + done.stderr)[-600:]}"
        )
    dbt_paths.logs.mkdir(parents=True, exist_ok=True)
    (dbt_paths.logs / "build.out").write_text(done.stdout + done.stderr, encoding="utf-8")
    results = run_results(dbt_paths)
    lake_dir = s.results_dir / "lake"
    _write_json(lake_dir / "dbt_results.json", {"data_cut": cut.isoformat(), **results})
    failed = [n for n in results["nodes"] if n["status"] not in ("success", "pass")]
    if done.returncode != 0 or failed:
        raise RuntimeError(
            f"dbt build failed on {len(failed)} nodes: "
            + "; ".join(f"{n['node']} {n['status']} {n['message']}" for n in failed[:8])
        )

    asof_report: dict[str, Any] | None = None
    if s.run_checks:
        macro_sql, planted_sql = checks.compile_macros(dbt_paths)
    con = connect(dbt_paths.work_db, s, dbt_paths.temp)
    try:
        if s.run_checks:
            asof_report = checks.run_checks(con, macro_sql, planted_sql, n_cves=s.check_cves)
            _write_json(lake_dir / "asof_tests.json", {"data_cut": cut.isoformat(), **asof_report})
        quarantine = [
            {"rule_id": r[0], "rule": r[1], "rows": int(r[2]), "cves": int(r[3])}
            for r in rows(
                con,
                "select rule_id, rule, row_count, cve_count from quarantine.quarantine_counts order by rule_id",
            )
        ]
        stats = _stats(con)
    finally:
        con.close()

    lake_sha = publish.write(dbt_paths.work_db, s.lake_file)
    lake_con = duckdb.connect(str(s.lake_file), read_only=True)
    try:
        digests = {t: table_digest(lake_con, t) for t in publish.PUBLISHED}
    finally:
        lake_con.close()
    completeness = {
        "data_cut": cut.isoformat(),
        "bronze": [asdict(t) for t in tables],
        "bronze_missing": [t.name for t in tables if not t.present],
        "config_rows": config_rows,
        "nvd_history_data": history_data,
        "nvd_history_ledger": history_ledger,
        **stats,
    }
    _write_json(lake_dir / "completeness.json", completeness)
    _write_json(lake_dir / "quarantine.json", {"data_cut": cut.isoformat(), "rules": quarantine})
    lake_report = {
        "data_cut": cut.isoformat(),
        "file": str(s.lake_file.relative_to(s.root))
        if s.lake_file.is_relative_to(s.root)
        else str(s.lake_file),
        "sha256": lake_sha,
        "bytes": s.lake_file.stat().st_size,
        "tables": digests,
        "content_digest": _content_digest(digests),
    }
    _write_json(lake_dir / "lake.json", lake_report)
    _write_json(lake_dir / "locks.json", locks_report(s.root / "data" / "locks", cut.isoformat()))
    _write_part(s, cut, lake_report, quarantine, completeness, asof_report, results)
    if not s.keep_work:
        dbt_paths.work_db.unlink(missing_ok=True)
        shutil.rmtree(dbt_paths.temp, ignore_errors=True)
    return {
        "seconds": round(time.monotonic() - started, 1),
        "data_cut": cut.isoformat(),
        "lake_sha256": lake_sha,
        "content_digest": lake_report["content_digest"],
        "asof_passed": None if asof_report is None else asof_report["passed"],
        "quarantine": {q["rule_id"]: q["rows"] for q in quarantine},
        "rows": {t: d["rows"] for t, d in digests.items()},
    }


def _content_digest(digests: dict[str, dict[str, Any]]) -> str:
    from unscheduled_core.hashing import sha256_json

    return sha256_json({t: d["digest"] for t, d in sorted(digests.items())})


def _stats(con: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    first = one(
        con,
        """
        select
            count(*) as cves,
            count(*) filter (where has_history) as cves_with_history,
            count(*) filter (where pre_history_facts > 0) as cves_with_pre_history_facts,
            count(*) filter (where before_history) as cves_before_history,
            count(*) filter (where published >= timestamptz '2017-01-01' and not has_history) as cves_since_2017_without_history,
            count(*) filter (where in_cvelist) as cves_in_cvelist,
            count(*) filter (where in_nvd) as cves_in_nvd
        from gold.cve_current
        """,
    )
    names = [
        "cves",
        "cves_with_history",
        "cves_with_pre_history_facts",
        "cves_before_history",
        "cves_since_2017_without_history",
        "cves_in_cvelist",
        "cves_in_nvd",
    ]
    out: dict[str, Any] = dict(zip(names, (int(x) for x in first), strict=True))
    out["sbom_non_package_components"] = {
        str(r[0]): int(r[1])
        for r in rows(con, "select type, sum(components) from config.sbom_non_package group by 1 order by 1")
    }
    out["sbom_package_components"] = int(one(con, "select count(*) from config.sbom_components")[0])
    out["facts_by_rule"] = {
        str(r[0]): int(r[1])
        for r in rows(con, "select dated_by, count(*) from silver.cve_fact group by 1 order by 1")
    }
    out["facts_by_field"] = {
        str(r[0]): int(r[1])
        for r in rows(con, "select field, count(*) from silver.cve_fact group by 1 order by 1")
    }
    out["coverage_by_window"] = coverage_by_window(con)
    return out


COVERAGE_COLUMNS = ("cves", "published", "nvd_band", "filer_band", "adp_band", "nvd_and_filer_band")


def coverage_by_window(con: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    """Per registered window: the CVEs in it, the published ones, and how many of those carry a CVSS
    severity band from the NVD (3.1), from the filer (3.1, 3.0 or 4.0), from CISA ADP (3.1), and
    from both the NVD and the filer. These are the labels Phase 2 can learn from, by window."""
    filer = "coalesce(filer_cvss31_band, filer_cvss30_band, filer_cvss40_band)"
    found = rows(
        con,
        f"""
        select
            split_window,
            count(*),
            count(*) filter (where state = 'PUBLISHED'),
            count(*) filter (where state = 'PUBLISHED' and nvd_cvss31_band is not null),
            count(*) filter (where state = 'PUBLISHED' and {filer} is not null),
            count(*) filter (where state = 'PUBLISHED' and adp_cvss31_band is not null),
            count(*) filter (where state = 'PUBLISHED' and nvd_cvss31_band is not null and {filer} is not null)
        from gold.cve_current
        where split_window is not null
        group by 1
        order by min(published), 1
        """,
    )
    return [
        {"window": str(r[0]), **dict(zip(COVERAGE_COLUMNS, (int(x) for x in r[1:]), strict=True))}
        for r in found
    ]


def _write_part(
    s: Settings,
    cut: datetime,
    lake: dict[str, Any],
    quarantine: list[dict[str, Any]],
    completeness: dict[str, Any],
    asof_report: dict[str, Any] | None,
    dbt: dict[str, Any],
) -> None:
    m = ManifestBuilder(cut.date().isoformat())
    origin = "scripts/build_lake.py"
    every = "every CVE in the CVE List or the NVD, as of the data cut"
    m.value(
        "lake.data_cut",
        cut.isoformat(),
        "text",
        origin=origin,
        population="the newest time any source was seen",
        source="lake",
    )
    m.value(
        "lake.sha256",
        lake["sha256"],
        "text",
        origin=origin,
        population="data/lake/unscheduled.duckdb",
        source="lake",
    )
    m.value(
        "lake.content_digest",
        lake["content_digest"],
        "text",
        origin=origin,
        population="every published table",
        source="lake",
    )
    m.value("lake.cves", completeness["cves"], "int", origin=origin, population=every, source="lake")
    m.value(
        "lake.facts",
        lake["tables"]["silver.cve_fact"]["rows"],
        "int",
        origin=origin,
        population="silver.cve_fact rows",
        source="lake",
    )
    for key in (
        "cves_with_history",
        "cves_with_pre_history_facts",
        "cves_before_history",
        "cves_since_2017_without_history",
    ):
        m.value(f"lake.{key}", completeness[key], "int", origin=origin, population=every, source="lake")
    hist = completeness["nvd_history_data"]
    m.value(
        "lake.history.events",
        hist["events"],
        "int",
        origin=origin,
        population="NVD change history events in bronze",
        source="lake",
    )
    m.value(
        "lake.history.share_of_months",
        hist["share_of_months"],
        "pct1",
        origin=origin,
        population="months from 2017-01 to the data cut that carry change events",
        source="lake",
    )
    for q in quarantine:
        m.value(
            f"lake.quarantine.{q['rule_id'].lower()}",
            q["rows"],
            "int",
            origin=origin,
            population=f"rows quarantined by {q['rule_id']}, {q['rule']}",
            source="lake",
        )
    non_package = completeness["sbom_non_package_components"]
    m.value(
        "lake.quarantine.q07_not_packages",
        int(sum(non_package.values())),
        "int",
        origin=origin,
        population="SBOM components that are not packages ("
        + ", ".join(f"{k} {v}" for k, v in non_package.items())
        + "), never carrying a package URL, so counted apart from Q07",
        source="lake",
    )
    windows = completeness.get("coverage_by_window", [])
    if windows:
        m.table(
            "lake.coverage_by_window",
            ["Window", "CVEs", "Published", "NVD band", "Filer band", "CISA ADP band", "NVD and filer band"],
            ["text", "int", "int", "int", "int", "int", "int"],
            [[w["window"], *(w[c] for c in COVERAGE_COLUMNS)] for w in windows],
            origin=origin,
            population="CVEs by the registered window of their publication (config/splits.yaml); a band "
            "is counted on published CVEs only",
            source="lake",
        )
        for w in windows:
            for c in COVERAGE_COLUMNS:
                m.value(
                    f"lake.window.{w['window']}.{c}",
                    w[c],
                    "int",
                    origin=origin,
                    population=f"CVEs published in the {w['window']} window"
                    + ("" if c == "cves" else ", rejected excluded"),
                    source="lake",
                )
    m.value(
        "lake.sbom.package_components",
        completeness["sbom_package_components"],
        "int",
        origin=origin,
        population="package components in the six SBOMs under customer/sboms",
        source="lake",
    )
    tests = dbt["summary"].get("test", {})
    m.value(
        "lake.dbt.tests_passed",
        int(tests.get("pass", 0)),
        "int",
        origin=origin,
        population="dbt tests in dbt/",
        source="lake",
    )
    m.value(
        "lake.dbt.tests_total",
        int(sum(tests.values())),
        "int",
        origin=origin,
        population="dbt tests in dbt/",
        source="lake",
    )
    m.value(
        "lake.dbt.models",
        int(sum(dbt["summary"].get("model", {}).values())),
        "int",
        origin=origin,
        population="dbt models",
        source="lake",
    )
    if asof_report is not None:
        population = f"{asof_report['cves']} sampled CVEs at {asof_report['times']} times"
        m.value(
            "lake.asof.frames_compared",
            asof_report["frames_compared"],
            "int",
            origin=origin,
            population=population,
            source="lake",
        )
        m.value(
            "lake.asof.parity_mismatches",
            asof_report["parity_mismatches"],
            "int",
            origin=origin,
            population=population,
            source="lake",
        )
        m.value(
            "lake.asof.planted_facts",
            asof_report["planted_facts"],
            "int",
            origin=origin,
            population=population,
            source="lake",
        )
        m.value(
            "lake.asof.planted_facts_returned",
            asof_report["planted_facts_returned"],
            "int",
            origin=origin,
            population=population,
            source="lake",
        )
        m.value(
            "lake.asof.facts_missing",
            asof_report["facts_missing"],
            "int",
            origin=origin,
            population=population,
            source="lake",
        )
    m.table(
        "lake.quarantine",
        ["Rule", "What it catches", "Rows", "CVEs"],
        ["text", "text", "int", "int"],
        [[q["rule_id"], q["rule"], q["rows"], q["cves"]] for q in quarantine],
        origin=origin,
        population="every rule, every row it moved",
        source="lake",
    )
    m.table(
        "lake.tables",
        ["Table", "Rows"],
        ["text", "int"],
        [[t, d["rows"]] for t, d in sorted(lake["tables"].items())],
        origin=origin,
        population="the tables of the lake file",
        source="lake",
    )
    _write_json(s.results_dir / "parts" / "lake.json", m.dump())
