"""The bronze contract: every table, its columns and types, its key and its partition.

Bronze is typed Parquet under data/bronze/<table>/, one directory per year for the large tables.
A frame that does not match its table exactly (a missing, extra or retyped column) raises
ContractError before anything is written, so a source that changes its shape stops the run instead
of writing a table the lake cannot read.

Keys say what makes a row new. Upsert tables keep the first row seen for a key, so a rerun over the
same input writes nothing and an observation time is the first time the build saw that exact fact.
Replace tables are snapshots rewritten whole by each run of their source.

Column notes, where a name alone could be read two ways:
- every time is an aware UTC timestamp in microseconds; a day is a date
- first_seen_commit (kev, ghsa) is the commit time of the first commit of the publisher's
  repository that carried the entry; first_added (vulnrichment) and first_seen (exploit_signals)
  are the same for the file of the CVE, module or template
- cve_records.snapshot_at is the time of the CVE List release the record came from; observed_at
  is the time the build first saw the metric or weakness (the snapshot time for the CVE List,
  the fetch time for the NVD API)
- nvd_cves.fetched_at is when the page that carried the record was fetched
- cpe_names holds one row per CPE name and modification: created is when the NVD created the name,
  so a model can take only the names that existed at a CVE's day 0; vendor and product keep the
  quoting of the CPE 2.3 formatted string
- epss_offsets.offset_days is the day offset after publication (0, 1, 7, 30 or 90), or -1 for the
  daily rows of a CVE listed in KEV
- osv_advisories.source_db is the database prefix of the advisory id, which the OSV schema
  defines as the publisher of the record
- cwe.abstraction is the Weakness_Abstraction of a weakness, or the element kind (Category up to
  CWE 4, Grouping from CWE 5.0) of an entry that gathers weaknesses; parents are the ChildOf
  targets in the Research Concepts view (CWE-1000)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import polars as pl

UTC_TS = pl.Datetime("us", "UTC")
STR = pl.String()
STRS = pl.List(pl.String())
BOOL = pl.Boolean()
I32 = pl.Int32()
I64 = pl.Int64()
F64 = pl.Float64()
DAY = pl.Date()

Partition = Literal["cve_year", "created_year", "published_year"]
Mode = Literal["upsert", "replace"]


class ContractError(ValueError):
    """A frame does not match its bronze table."""


@dataclass(frozen=True)
class Table:
    name: str
    columns: dict[str, pl.DataType]
    key: tuple[str, ...]
    mode: Mode = "upsert"
    partition: Partition | None = None
    order: tuple[str, ...] = ()

    @property
    def schema(self) -> pl.Schema:
        return pl.Schema(self.columns)

    @property
    def sort_by(self) -> list[str]:
        return list(dict.fromkeys([*self.key, *self.order]))


TABLES: dict[str, Table] = {
    t.name: t
    for t in (
        Table(
            "cve_records",
            {
                "cve_id": STR,
                "state": STR,
                "assigner_org_id": STR,
                "assigner_short_name": STR,
                "date_reserved": UTC_TS,
                "date_published": UTC_TS,
                "date_updated": UTC_TS,
                "description": STR,
                "problem_cwes": STRS,
                "affected_json": STR,
                "has_affected_versions": BOOL,
                "references_count": I32,
                "adp_cisa_present": BOOL,
                "snapshot_at": UTC_TS,
                "record_digest": STR,
            },
            key=("cve_id", "record_digest"),
            partition="cve_year",
            order=("snapshot_at",),
        ),
        Table(
            "cve_metrics",
            {
                "cve_id": STR,
                "source": STR,
                "source_type": STR,
                "version": STR,
                "vector": STR,
                "base_score": F64,
                "base_severity": STR,
                "origin": STR,
                "observed_at": UTC_TS,
            },
            key=(
                "cve_id",
                "origin",
                "source",
                "source_type",
                "version",
                "vector",
                "base_score",
                "base_severity",
            ),
            partition="cve_year",
            order=("observed_at",),
        ),
        Table(
            "cve_weaknesses",
            {
                "cve_id": STR,
                "source": STR,
                "cwe_id": STR,
                "origin": STR,
                "observed_at": UTC_TS,
            },
            key=("cve_id", "origin", "source", "cwe_id"),
            partition="cve_year",
            order=("observed_at",),
        ),
        Table(
            "nvd_cves",
            {
                "cve_id": STR,
                "vuln_status": STR,
                "published": UTC_TS,
                "last_modified": UTC_TS,
                "source_identifier": STR,
                "has_cpe": BOOL,
                "cpe_count": I32,
                "cisa_exploit_add": DAY,
                "fetched_at": UTC_TS,
            },
            key=("cve_id", "last_modified", "vuln_status"),
            partition="cve_year",
            order=("fetched_at",),
        ),
        Table(
            "cpe_names",
            {
                "cpe_name_id": STR,
                "part": STR,
                "vendor": STR,
                "product": STR,
                "created": UTC_TS,
                "last_modified": UTC_TS,
                "deprecated": BOOL,
                "fetched_at": UTC_TS,
            },
            key=("cpe_name_id", "last_modified"),
            partition="created_year",
            order=("fetched_at",),
        ),
        Table(
            "nvd_changes",
            {
                "cve_id": STR,
                "event_name": STR,
                "cve_change_id": STR,
                "source_identifier": STR,
                "created": UTC_TS,
                "details_json": STR,
            },
            key=("cve_change_id",),
            partition="created_year",
            order=("created",),
        ),
        Table(
            "kev",
            {
                "cve_id": STR,
                "vendor_project": STR,
                "product": STR,
                "vulnerability_name": STR,
                "date_added": DAY,
                "due_date": DAY,
                "known_ransomware": STR,
                "cwes": STRS,
                "catalog_version": STR,
                "first_seen_commit": UTC_TS,
            },
            key=("cve_id", "catalog_version"),
        ),
        Table(
            "epss_offsets",
            {
                "cve_id": STR,
                "score_date": DAY,
                "epss": F64,
                "percentile": F64,
                "model_version": STR,
                "offset_days": I32,
            },
            key=("cve_id", "score_date", "offset_days"),
            partition="cve_year",
        ),
        Table(
            "osv_advisories",
            {
                "id": STR,
                "ecosystem": STR,
                "aliases": STRS,
                "published": UTC_TS,
                "modified": UTC_TS,
                "withdrawn": UTC_TS,
                "summary": STR,
                "severity_json": STR,
                "affected_json": STR,
                "source_db": STR,
            },
            key=("id", "ecosystem", "modified"),
            partition="published_year",
        ),
        Table(
            "ghsa",
            {
                "ghsa_id": STR,
                "cve_ids": STRS,
                "published": UTC_TS,
                "modified": UTC_TS,
                "withdrawn": UTC_TS,
                "severity": STR,
                "cwe_ids": STRS,
                "affected_json": STR,
                "first_seen_commit": UTC_TS,
            },
            key=("ghsa_id", "modified"),
        ),
        Table(
            "vulnrichment",
            {
                "cve_id": STR,
                "ssvc_exploitation": STR,
                "ssvc_automatable": STR,
                "ssvc_technical_impact": STR,
                "adp_cvss_vector": STR,
                "adp_cwes": STRS,
                "first_added": UTC_TS,
                "last_modified": UTC_TS,
            },
            key=("cve_id", "last_modified"),
            partition="cve_year",
        ),
        Table(
            "cwe",
            {
                "cwe_id": STR,
                "name": STR,
                "abstraction": STR,
                "parents": STRS,
            },
            key=("cwe_id",),
            mode="replace",
        ),
        Table(
            "exploit_signals",
            {
                "cve_id": STR,
                "source": STR,
                "path": STR,
                "first_seen": UTC_TS,
            },
            key=("cve_id", "source", "path"),
            mode="replace",
        ),
    )
}


def table(name: str) -> Table:
    if name not in TABLES:
        raise ContractError(f"bronze has no table {name!r}")
    return TABLES[name]


def empty(name: str) -> pl.DataFrame:
    return pl.DataFrame(schema=table(name).schema)


def frame(name: str, rows: list[dict[str, object]]) -> pl.DataFrame:
    """A frame of one table from row dicts, typed by the contract and checked against it."""
    spec = table(name)
    if not rows:
        return empty(name)
    data = {col: [r.get(col) for r in rows] for col in spec.columns}
    for r in rows:
        extra = set(r) - set(spec.columns)
        if extra:
            raise ContractError(f"{name}: columns outside the contract {sorted(extra)}")
    try:
        df = pl.DataFrame(data, schema=spec.schema, strict=True)
    except (TypeError, pl.exceptions.PolarsError) as err:
        raise ContractError(f"{name}: rows do not fit the contract: {err}") from err
    return conform(name, df)


def conform(name: str, df: pl.DataFrame) -> pl.DataFrame:
    """Return the frame with its columns in contract order, or raise ContractError."""
    spec = table(name)
    have = dict(df.schema)
    missing = [c for c in spec.columns if c not in have]
    extra = [c for c in have if c not in spec.columns]
    if missing or extra:
        raise ContractError(f"{name}: missing {missing}, outside the contract {extra}")
    wrong = [f"{c} is {have[c]}, not {t}" for c, t in spec.columns.items() if have[c] != t]
    if wrong:
        raise ContractError(f"{name}: " + "; ".join(wrong))
    nulls = [k for k in spec.key if df.get_column(k).null_count() and k not in _NULLABLE_KEYS]
    if nulls:
        raise ContractError(f"{name}: key columns with nulls {nulls}")
    return df.select(list(spec.columns))


# Key columns a source may leave empty: a metric without a severity, an advisory without a date.
_NULLABLE_KEYS = frozenset({"base_score", "base_severity", "vector", "version", "modified", "last_modified"})
