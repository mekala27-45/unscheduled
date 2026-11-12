"""Writing the lake file: silver, gold, quarantine and config, copied out of the work database.

The work database also holds staging views over local Parquet paths and intermediate tables; none
of that belongs in a file other people download. The lake file is written fresh each build, each
table in a fixed order, then checkpointed, and its digest is taken from the closed file.
"""

from __future__ import annotations

from pathlib import Path

import duckdb
from unscheduled_core.hashing import sha256_file

from unscheduled_lake.db import run

# Every table the lake file publishes, with the order its rows are written in. advisory_versions is
# published without the affected ranges themselves: they stay in bronze (osv_advisories, ghsa), keyed
# by the same advisory id and modified time, and would triple the size of the file.
DROPPED: dict[str, tuple[str, ...]] = {"silver.advisory_versions": ("affected_json",)}
PUBLISHED: dict[str, str] = {
    "silver.cve_fact": "cve_id, field, source, known_from, value",
    "silver.nvd_status_history": "cve_id, status_from",
    "silver.kev_events": "cve_id",
    "silver.exploit_first_seen": "cve_id",
    "silver.advisory_versions": "database, advisory_id, ecosystem, known_from",
    "gold.cve_current": "cve_id",
    "gold.mart_backlog_q1": "cve_id",
    "gold.mart_backlog_q2": "cve_id",
    "gold.mart_backlog_q3": "cve_id",
    "gold.mart_filer_vs_nvd": "cve_id",
    "gold.mart_kev_timing": "cve_id",
    "gold.mart_backlog_q6": "published_month, filer",
    "gold.mart_domain_shift": "position",
    "quarantine.quarantine": "rule_id, relation, row_key",
    "quarantine.quarantine_counts": "rule_id",
    "config.splits": "start_day",
    "config.status_labels": "status",
    "config.filer_types": "short_name, org_id",
    "config.bronze_tables": "name",
    "config.lake_build": "data_cut",
}


def write(work_db: Path, lake_file: Path, tables: dict[str, str] | None = None) -> str:
    """Copy the published tables into a new lake file; return the file's sha256."""
    tables = tables or PUBLISHED
    lake_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = lake_file.with_name(lake_file.name + ".tmp")
    for stale in (tmp, tmp.with_name(tmp.name + ".wal")):
        stale.unlink(missing_ok=True)
    con = duckdb.connect(str(work_db))
    try:
        run(con, "set threads = 1")
        run(con, "set preserve_insertion_order = true")
        # Strings dominate the lake (descriptions, vectors, ids) and compress best with zstd.
        run(con, "set force_compression = 'zstd'")
        run(con, f"attach '{_sql(tmp)}' as lake")
        for schema in sorted({t.split(".", 1)[0] for t in tables}):
            run(con, f"create schema lake.{schema}")
        for table, order in tables.items():
            drop = DROPPED.get(table, ())
            cols = f"* exclude ({', '.join(drop)})" if drop else "*"
            run(con, f"create table lake.{table} as select {cols} from {table} order by {order}")
        run(con, "checkpoint lake")
        run(con, "detach lake")
    finally:
        con.close()
    tmp.replace(lake_file)
    return sha256_file(lake_file)


def _sql(path: Path) -> str:
    return str(path).replace("'", "''")
