"""The training sets of Phase 2, point in time.

One row per published CVE, rejected excluded, in the windows train, development, test and shadow;
the gap window goes into no model. Every feature is what was known at day 0, the end of the
publication day in UTC: a fact from silver.cve_fact with known_from at or before day 0 and no
known_to before it, or the description the NVD change history holds at day 0. The labels are read
at the lake cut. EPSS, KEV and every NVD value are never features (evaluation/phase2_plan.yaml).

Inputs and labels go to separate files per split. The test labels sit in a file of their own,
TEST_LABELS, that only scripts/score_test.py opens: scripts/check_test_labels.py fails on any other
reference to it, and load_labels refuses the test split unless the caller unseals it.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

import duckdb
import polars as pl
from unscheduled_lake.digest import table_digest

SPLITS = ("train", "development", "test", "shadow")
BANDS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
CWE_CLASSES = 50
TEST_LABELS = "test_labels.parquet"
DAY0_FIELDS = (
    "cvss31_vector",
    "cvss30_vector",
    "cvss40_vector",
    "cvss31_severity",
    "cvss30_severity",
    "cwe",
    "ssvc_exploitation",
    "ssvc_automatable",
    "ssvc_technical_impact",
    "exploit_code",
)
INPUT_COLUMNS = (
    "cve_id",
    "split",
    "published",
    "published_year",
    "published_month",
    "reserved_to_published_days",
    "filer",
    "filer_type",
    "description",
    "description_rule",
    "products",
    "affected_rule",
    "affected_entries",
    "vendor_present",
    "product_present",
    "versions_present",
    "filer_cvss31_vector",
    "filer_cvss30_vector",
    "filer_cvss40_vector",
    "filer_band",
    *(f"filer_{m}" for m in METRICS),
    "filer_cwes",
    "adp_cvss31_vector",
    "adp_band",
    "adp_cwes",
    "adp_ssvc_exploitation",
    "adp_ssvc_automatable",
    "adp_ssvc_technical_impact",
    "exploit_code_by_day0",
    "text",
)
LABEL_COLUMNS = (
    "cve_id",
    "split",
    "band",
    *(f"nvd_{m}" for m in METRICS),
    "nvd_cwes",
    "cwe",
    "kev_180",
    "kev_q03",
    "days_to_kev",
    "kev_event",
)


def joined_text(
    description: str | None,
    filer: str | None,
    products: str | None,
    filer_vector: str | None = None,
    adp_band: str | None = None,
    ssvc_exploitation: str | None = None,
) -> str:
    """The one text field every text model reads. It carries the day 0 description, the filer, the
    products, and the structured values the floors also get one hot (the filer vector, the CISA ADP
    band and SSVC exploitation when known at day 0), so a text model and its floor see the same
    inputs."""
    parts = [(description or "").strip()]
    if filer:
        parts.append(f"Filer: {filer}")
    if products:
        parts.append(f"Products: {products}")
    if filer_vector:
        parts.append(f"Filer score: {filer_vector}")
    if adp_band:
        parts.append(f"CISA ADP severity: {adp_band}")
    if ssvc_exploitation:
        parts.append(f"CISA SSVC exploitation: {ssvc_exploitation}")
    return "\n".join(p for p in parts if p)


def labels_name(split: str) -> str:
    return TEST_LABELS if split == "test" else f"{split}_labels.parquet"


def inputs_name(split: str) -> str:
    return f"{split}_inputs.parquet"


def load_labels(folder: Path, split: str, *, unsealed: bool = False) -> pl.DataFrame:
    """The labels of a split. The test labels open only for the scorer, which unseals them."""
    if split == "test" and not unsealed:
        raise PermissionError("the test labels are read once, by scripts/score_test.py")
    return pl.read_parquet(folder / labels_name(split))


def attach_bronze(con: duckdb.DuckDBPyConnection, bronze: Path) -> None:
    """The two bronze tables the sets read beside the lake: the NVD change history, for the day 0
    description, and the CVE List records, for the affected vendor and product names."""
    for view, table in (("nvd_changes_bronze", "nvd_changes"), ("cve_records_bronze", "cve_records")):
        glob = (bronze / table / "**" / "*.parquet").as_posix()
        con.execute(
            f"create or replace temp view {view} as "
            f"select * from read_parquet('{glob}', union_by_name = true, hive_partitioning = false)"
        )


def _metric_sql(column: str, prefix: str) -> str:
    return ", ".join(f"regexp_extract({column}, '/{m}:([A-Z])', 1) as {prefix}{m}" for m in METRICS)


SET_SQL = f"""
set TimeZone = 'UTC';

create or replace temp table set_cves as
select
    cve_id,
    published,
    split_window as split,
    filer,
    filer_type,
    date_reserved,
    date_trunc('day', published) + interval 1 day as t0,
    description as description_now,
    nvd_cvss31_band,
    nvd_cvss31_vector,
    nvd_cwes,
    kev_date_added
from gold.cve_current
where published is not null
    and coalesce(state, '') <> 'REJECTED'
    and split_window in ('train', 'development', 'test', 'shadow');

create or replace temp table set_facts as
select f.cve_id, f.field, f.source, f.value, f.known_from, f.source = c.filer as by_filer
from silver.cve_fact as f
join set_cves as c using (cve_id)
where f.known_from <= c.t0
    and (f.known_to is null or f.known_to > c.t0)
    and f.field in ({", ".join(f"'{x}'" for x in DAY0_FIELDS)});

create or replace temp table set_features as
select
    c.cve_id,
    max_by(f.value, f.known_from) filter (where f.field = 'cvss31_vector' and f.by_filer) as filer_cvss31_vector,
    max_by(f.value, f.known_from) filter (where f.field = 'cvss30_vector' and f.by_filer) as filer_cvss30_vector,
    max_by(f.value, f.known_from) filter (where f.field = 'cvss40_vector' and f.by_filer) as filer_cvss40_vector,
    max_by(f.value, f.known_from) filter (where f.field = 'cvss31_severity' and f.by_filer) as filer_band31,
    max_by(f.value, f.known_from) filter (where f.field = 'cvss30_severity' and f.by_filer) as filer_band30,
    list(distinct f.value order by f.value) filter (where f.field = 'cwe' and f.by_filer) as filer_cwes,
    max_by(f.value, f.known_from) filter (where f.field = 'cvss31_vector' and f.source = 'CISA-ADP') as adp_cvss31_vector,
    max_by(f.value, f.known_from) filter (where f.field = 'cvss31_severity' and f.source = 'CISA-ADP') as adp_band,
    list(distinct f.value order by f.value) filter (where f.field = 'cwe' and f.source = 'CISA-ADP') as adp_cwes,
    max_by(f.value, f.known_from) filter (where f.field = 'ssvc_exploitation') as adp_ssvc_exploitation,
    max_by(f.value, f.known_from) filter (where f.field = 'ssvc_automatable') as adp_ssvc_automatable,
    max_by(f.value, f.known_from) filter (where f.field = 'ssvc_technical_impact') as adp_ssvc_technical_impact,
    coalesce(bool_or(f.field = 'exploit_code'), false) as exploit_code_by_day0
from set_cves as c
left join set_facts as f using (cve_id)
group by c.cve_id;

create or replace temp table set_description as
with events as (
    select e.cve_id, e.created, e.cve_change_id, u.d.newValue as description
    from nvd_changes_bronze as e,
        unnest(from_json(e.details_json, '[{{"action":"VARCHAR","type":"VARCHAR","newValue":"VARCHAR"}}]')) as u(d)
    where u.d.type = 'Description'
        and u.d.action in ('Added', 'Changed')
        and u.d.newValue is not null
        and e.cve_id in (select cve_id from set_cves)
)
select e.cve_id, e.description as description_day0
from events as e
join set_cves as c on c.cve_id = e.cve_id and e.created <= c.t0
qualify row_number() over (partition by e.cve_id order by e.created desc, e.cve_change_id desc) = 1;

create or replace temp table set_affected as
with latest as (
    select cve_id, affected_json, has_affected_versions
    from cve_records_bronze
    where cve_id in (select cve_id from set_cves)
    qualify row_number() over (partition by cve_id order by snapshot_at desc, record_digest desc) = 1
),
entries as (
    select
        l.cve_id,
        l.has_affected_versions,
        nullif(trim(coalesce(u.a.vendor, '')), 'n/a') as vendor,
        nullif(trim(coalesce(u.a.product, '')), 'n/a') as product
    from latest as l,
        unnest(from_json(coalesce(l.affected_json, '[]'), '[{{"vendor":"VARCHAR","product":"VARCHAR"}}]')) as u(a)
)
select
    cve_id,
    count(*) as affected_entries,
    coalesce(bool_or(has_affected_versions), false) as versions_present,
    coalesce(bool_or(coalesce(vendor, '') <> ''), false) as vendor_present,
    coalesce(bool_or(coalesce(product, '') <> ''), false) as product_present,
    string_agg(distinct trim(coalesce(vendor, '') || ' ' || coalesce(product, '')), '; '
        order by trim(coalesce(vendor, '') || ' ' || coalesce(product, '')))
        filter (where coalesce(vendor, '') <> '' or coalesce(product, '') <> '') as products
from entries
group by cve_id;

create or replace temp table set_rows as
select
    c.cve_id,
    c.split,
    c.published,
    year(c.published) as published_year,
    year(c.published) * 12 + month(c.published) as published_month,
    date_diff('day', c.date_reserved, c.published) as reserved_to_published_days,
    c.filer,
    c.filer_type,
    coalesce(d.description_day0, c.description_now) as description,
    case when d.description_day0 is null then 'current' else 'history' end as description_rule,
    a.products,
    'current' as affected_rule,
    coalesce(a.affected_entries, 0) as affected_entries,
    coalesce(a.vendor_present, false) as vendor_present,
    coalesce(a.product_present, false) as product_present,
    coalesce(a.versions_present, false) as versions_present,
    f.filer_cvss31_vector,
    f.filer_cvss30_vector,
    f.filer_cvss40_vector,
    upper(coalesce(f.filer_band31, f.filer_band30)) as filer_band,
    {_metric_sql("coalesce(f.filer_cvss31_vector, f.filer_cvss30_vector)", "filer_")},
    f.filer_cwes,
    f.adp_cvss31_vector,
    upper(f.adp_band) as adp_band,
    f.adp_cwes,
    f.adp_ssvc_exploitation,
    f.adp_ssvc_automatable,
    f.adp_ssvc_technical_impact,
    f.exploit_code_by_day0,
    case when upper(c.nvd_cvss31_band) in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') then upper(c.nvd_cvss31_band) end as band,
    upper(c.nvd_cvss31_band) = 'NONE' as band_none,
    {_metric_sql("c.nvd_cvss31_vector", "nvd_")},
    c.nvd_cwes,
    c.kev_date_added is not null and c.kev_date_added < cast(c.published as date) as kev_q03,
    c.kev_date_added is not null
        and c.kev_date_added >= cast(c.published as date)
        and date_diff('day', cast(c.published as date), c.kev_date_added) <= 180 as kev_180,
    case
        when c.kev_date_added is not null and c.kev_date_added >= cast(c.published as date)
            then date_diff('day', cast(c.published as date), c.kev_date_added)
        else date_diff('day', cast(c.published as date), cast($cut as date))
    end as days_to_kev,
    c.kev_date_added is not null and c.kev_date_added >= cast(c.published as date) as kev_event
from set_cves as c
left join set_features as f using (cve_id)
left join set_description as d using (cve_id)
left join set_affected as a using (cve_id);
"""


def lake_cut(con: duckdb.DuckDBPyConnection) -> str:
    row = con.execute("select cast(max(data_cut) as varchar) from config.lake_build").fetchone()
    if row is None or row[0] is None:
        raise ValueError("the lake has no data cut in config.lake_build")
    return str(row[0])


def build_frame(con: duckdb.DuckDBPyConnection) -> pl.DataFrame:
    """Every set row, inputs and labels together, sorted by CVE id. The connection must hold the
    lake tables and the two bronze views (attach_bronze)."""
    cut = lake_cut(con)
    for statement in [s for s in SET_SQL.split(";\n") if s.strip()]:
        con.execute(statement, {"cut": cut} if "$cut" in statement else None)
    frame = con.sql("select * from set_rows order by cve_id").pl()
    filer_vector = frame.select(
        pl.coalesce("filer_cvss31_vector", "filer_cvss30_vector", "filer_cvss40_vector")
    ).to_series()
    columns = [
        frame.get_column("description").to_list(),
        frame.get_column("filer").to_list(),
        frame.get_column("products").to_list(),
        filer_vector.to_list(),
        frame.get_column("adp_band").to_list(),
        frame.get_column("adp_ssvc_exploitation").to_list(),
    ]
    text = [joined_text(*row) for row in zip(*columns, strict=True)]
    frame = frame.with_columns(pl.Series("text", text, dtype=pl.String))
    return with_cwe_label(frame)


def with_cwe_label(frame: pl.DataFrame) -> pl.DataFrame:
    """The CWE label: the NVD value most frequent in train among the set a CVE carries, as one of
    the CWE_CLASSES most frequent in train, every other value as other. Ties break by the value."""
    counts: Counter[str] = Counter()
    for values in frame.filter(pl.col("split") == "train").get_column("nvd_cwes").to_list():
        counts.update(values or [])
    classes = {v for v, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:CWE_CLASSES]}

    def pick(values: list[str] | None) -> str | None:
        if not values:
            return None
        best = sorted(values, key=lambda v: (-counts.get(v, 0), v))[0]
        return best if best in classes else "other"

    picks = [pick(values) for values in frame.get_column("nvd_cwes").to_list()]
    return frame.with_columns(pl.Series("cwe", picks, dtype=pl.String))


def content_digest(path: Path) -> str:
    """The exact digest over the rows of a Parquet file, independent of its byte layout."""
    con = duckdb.connect()
    try:
        con.execute(f"create view set_file as select * from read_parquet('{path.as_posix()}')")
        return str(table_digest(con, "main.set_file")["digest"])
    finally:
        con.close()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def coverage(frame: pl.DataFrame) -> dict[str, dict[str, Any]]:
    """Per split: rows, label coverage, class balance and the share of rows with each feature."""
    out: dict[str, dict[str, Any]] = {}
    for split in SPLITS:
        part = frame.filter(pl.col("split") == split)
        n = part.height

        def share(expr: pl.Expr, part: pl.DataFrame = part, n: int = n) -> float:
            return round(float(part.select(expr.cast(pl.Float64).mean()).item() or 0.0), 6) if n else 0.0

        out[split] = {
            "rows": n,
            "with_band": int(part.get_column("band").is_not_null().sum()),
            "band_none": int(part.get_column("band_none").fill_null(False).sum()),
            "bands": {b: int((part.get_column("band") == b).sum()) for b in BANDS},
            "with_metrics": int(part.get_column("nvd_AV").fill_null("").ne("").sum()),
            "with_cwe": int(part.get_column("cwe").is_not_null().sum()),
            "kev_180": int(part.get_column("kev_180").fill_null(False).sum()),
            "kev_q03": int(part.get_column("kev_q03").fill_null(False).sum()),
            "description_from_history": int((part.get_column("description_rule") == "history").sum()),
            "feature_share": {
                "filer_band": share(pl.col("filer_band").is_not_null()),
                "filer_cvss31_vector": share(pl.col("filer_cvss31_vector").is_not_null()),
                "filer_cvss40_vector": share(pl.col("filer_cvss40_vector").is_not_null()),
                "filer_cwes": share(pl.col("filer_cwes").list.len().fill_null(0) > 0),
                "adp_band": share(pl.col("adp_band").is_not_null()),
                "adp_ssvc_exploitation": share(pl.col("adp_ssvc_exploitation").is_not_null()),
                "products": share(pl.col("products").is_not_null()),
                "exploit_code_by_day0": share(pl.col("exploit_code_by_day0").fill_null(False)),
                "description": share(pl.col("description").fill_null("").str.len_chars() > 0),
            },
        }
    return out


def empty_columns(frame: pl.DataFrame) -> list[str]:
    """Input columns empty for a whole window in which the source could have filled them. The CISA
    ADP container and the filer CVSS 4.0 vector began in 2024 and 2023, so they are judged only on
    the windows after; everything else on every window."""
    late = {
        "adp_cvss31_vector",
        "adp_band",
        "adp_cwes",
        "adp_ssvc_exploitation",
        "adp_ssvc_automatable",
        "adp_ssvc_technical_impact",
        "filer_cvss40_vector",
    }
    problems = []
    for split in SPLITS:
        part = frame.filter(pl.col("split") == split)
        if part.height == 0:
            problems.append(f"{split}: no rows")
            continue
        for column in INPUT_COLUMNS:
            if column in {"cve_id", "split"} or (column in late and split == "train"):
                continue
            series = part.get_column(column)
            filled = series.is_not_null()
            if series.dtype == pl.String:
                filled = filled & (series.fill_null("") != "")
            elif isinstance(series.dtype, pl.List):
                filled = filled & (series.list.len().fill_null(0) > 0)
            if not bool(filled.any()):
                problems.append(f"{split}: {column}")
    return problems


def write(frame: pl.DataFrame, out: Path) -> dict[str, Any]:
    """Inputs and labels per split, each sorted by CVE id, with their exact content digests."""
    out.mkdir(parents=True, exist_ok=True)
    files: dict[str, Any] = {}
    for split in SPLITS:
        part = frame.filter(pl.col("split") == split).sort("cve_id")
        for name, columns in ((inputs_name(split), INPUT_COLUMNS), (labels_name(split), LABEL_COLUMNS)):
            path = out / name
            part.select(columns).write_parquet(path, compression="zstd", statistics=True)
            files[name] = {"rows": part.height, "content_digest": content_digest(path)}
    return files


def build(lake_file: Path, bronze: Path, out: Path) -> dict[str, Any]:
    con = duckdb.connect(str(lake_file), read_only=True)
    try:
        attach_bronze(con, bronze)
        cut = lake_cut(con)
        frame = build_frame(con)
    finally:
        con.close()
    problems = empty_columns(frame)
    if problems:
        raise ValueError("a feature column is empty for a whole window: " + ", ".join(problems))
    files = write(frame, out)
    record = {
        "lake_cut": cut,
        "scoring_time": "day 0, the end of the publication day in UTC",
        "files": files,
        "coverage": coverage(frame),
        "cwe_classes": sorted(v for v in frame.get_column("cwe").unique().to_list() if v is not None),
    }
    (out / "manifest.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return record
