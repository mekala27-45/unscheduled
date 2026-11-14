"""Build the serving bundle the API loads into Neon: data/serving/ with its manifest of digests.

    python scripts/build_serving_bundle.py

From the lake file, for every CVE published since 2021-01-01 and every KEV listed CVE:

    cve.parquet          the current state of each CVE, compact, with provenance_json: for each
                         served field, the source that gave it and when it became known
    cve_event.parquet    the ruler: every dated event of each CVE (published, NVD status changes,
                         every vector, CWE and SSVC a source set or removed, the KEV listing, the
                         first exploit code per source, EPSS at the registered offsets for KEV CVEs)
    product.parquet      the six stand in products: who they play, the repository or image and
                         its pin, the licence and stars as read when the rule was applied
    finding.parquet      every finding of results/exposure, at each product's pin and today, with
                         the matched range, the fixed versions and when the advisory was known
    backlog.json         the Q1 to Q6 charts, every value read from results/backlog
    bundle_manifest.json every file with its sha256 and rows, when it was generated, the data cut,
                         the digest of the lake it came from, the locks by source, and the
                         quarantine counts and the newest run ledger rows for the data page

Every file is written in a fixed row order with one thread, so the same lake gives the same bytes.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import duckdb
import polars as pl
import yaml
from unscheduled_core import paths
from unscheduled_core.hashing import sha256_file

POPULATION = """
create temp table served as
select cve_id from gold.cve_current
where state <> 'REJECTED' and (published >= timestamptz '2021-01-01 00:00:00+00' or kev_listed)
"""

# Provenance only for the two served fields that neither an event nor the row itself dates: the
# CWEs and the CPE flag. The API dates the publication, the state, the filer, its type and the
# description from the published column, the last change from itself and EPSS from its own date
# (unscheduled_api.asof, DERIVED), and every other field by the newest event that sets it (EVENTS
# below), so the object stays small enough for the free plan (DECISIONS.md, 12 November 2026).
PROVENANCE = """
create temp table provenance as
with cur as (
    select f.cve_id, f.field, f.source, f.known_from, f.dated_by
    from silver.cve_fact as f
    join served using (cve_id)
    where f.known_to is null and f.field in ('cwe', 'cpe_config')
),
first_per_field as (
    select cve_id,
        case field when 'cwe' then 'cwes' else 'has_cpe' end as served_field,
        arg_min(source, known_from) as source,
        min(known_from) as known_from,
        arg_min(dated_by, known_from) as rule
    from cur
    group by all
)
select cve_id,
    to_json(map_from_entries(list(
        struct_pack(k := served_field, v := struct_pack(
            source := source,
            known_from := strftime(known_from, '%Y-%m-%dT%H:%M:%S.%fZ'),
            rule := rule
        ))
        order by served_field
    ))) as provenance_json
from first_per_field
where known_from is not null
group by cve_id
"""

# Exactly the columns of the API's contract (unscheduled_api.bundle.CVE_COLUMNS), in its order.
CVE = """
select
    c.cve_id,
    c.state,
    c.published,
    coalesce(greatest(c.date_updated, c.nvd_last_modified), c.date_updated, c.nvd_last_modified)
        as last_modified,
    c.nvd_status,
    c.nvd_status_since,
    c.filer,
    c.filer_type,
    c.description,
    list_sort(list_distinct(list_transform(
        list_concat(coalesce(c.filer_cwes, []), coalesce(c.nvd_cwes, []), coalesce(c.adp_cwes, [])),
        lambda x: case upper(x) when 'NVD-CWE-OTHER' then 'NVD-CWE-Other' when 'NVD-CWE-NOINFO' then 'NVD-CWE-noinfo'
             else x end
    ))) as cwes,
    c.filer_cvss31_vector, c.filer_cvss31_score, c.filer_cvss31_band,
    c.filer_cvss40_vector, c.filer_cvss40_score, c.filer_cvss40_band,
    c.nvd_cvss31_vector, c.nvd_cvss31_score, c.nvd_cvss31_band,
    c.adp_cvss31_vector, c.adp_cvss31_score, c.adp_cvss31_band,
    c.ssvc_exploitation, c.ssvc_automatable, c.ssvc_technical_impact,
    c.kev_date_added,
    c.kev_ransomware,
    c.epss as epss_score,
    cast(null as double) as epss_percentile,
    c.epss_date,
    cast(c.first_exploit_at as date) as exploit_first_seen,
    c.has_cpe,
    cast(coalesce(p.provenance_json, '{}') as varchar) as provenance_json
from gold.cve_current as c
join served using (cve_id)
left join provenance as p using (cve_id)
order by c.cve_id
"""

# The served fields a vector of a source sets: the filer's 3.1 and 4.0, the NVD's and CISA's 3.1.
VECTOR_PREFIX = """case
    when {f} = 'cvss31_vector' and {s} = {filer} then 'filer_cvss31'
    when {f} = 'cvss40_vector' and {s} = {filer} then 'filer_cvss40'
    when {f} = 'cvss31_vector' and {s} = 'nvd@nist.gov' then 'nvd_cvss31'
    when {f} = 'cvss31_vector' and {s} = 'CISA-ADP' then 'adp_cvss31'
end"""

EVENTS = f"""
-- The ruler of each served CVE, only the events the console draws or the as-of view reads (the
-- publication is the published column of cve.parquet, so it is no event here): every NVD status, the vectors of the filer, the NVD and CISA (with their score and
-- band), CISA's SSVC decision (one event per change of the three points), the KEV listing, the
-- first exploit code per source, EPSS at the registered offsets for KEV CVEs, a rejection, and a
-- removal of any of those. sets names the served fields an event gives a value to (null when
-- removed), and the API dates each of those fields by its newest event (unscheduled_api.asof).
with facts as (
    select f.cve_id, f.field, f.source, f.value, f.known_from, f.known_to, f.dated_by,
        c.published, c.filer, c.kev_listed, c.kev_date_added
    from silver.cve_fact as f
    join served using (cve_id)
    join gold.cve_current as c using (cve_id)
    where f.field in (
        'nvd_status', 'cvss31_vector', 'cvss40_vector', 'cvss31_score', 'cvss40_score', 'cvss31_severity',
        'cvss40_severity', 'ssvc_exploitation', 'ssvc_automatable', 'ssvc_technical_impact', 'kev_listed',
        'kev_ransomware', 'exploit_code', 'epss', 'cve_state'
    )
),
scores as (
    select cve_id, replace(field, '_score', '_vector') as vector_field, source, known_from, value as score
    from facts where field like 'cvss%_score'
),
bands as (
    select cve_id, replace(field, '_severity', '_vector') as vector_field, source, known_from, value as band
    from facts where field like 'cvss%_severity'
),
series as (
    select
        f.*,
        row_number() over (partition by f.cve_id, f.field, f.source order by f.known_from, f.value) as nth,
        {VECTOR_PREFIX.format(f="f.field", s="f.source", filer="f.filer")} as vector_prefix
    from facts as f
    where f.field not like 'cvss%_score' and f.field not like 'cvss%_severity'
),
kept as (
    select s.*,
        s.field = 'exploit_code' and s.known_from = min(s.known_from) over (partition by s.cve_id, s.field)
            as first_exploit
    from series as s
    where (s.field in ('cvss31_vector', 'cvss40_vector') and s.vector_prefix is not null)
       or s.field in ('nvd_status', 'kev_listed', 'kev_ransomware')
       or (s.field = 'exploit_code' and s.nth = 1)
       or (s.field = 'cve_state' and s.value = 'REJECTED')
       or (s.field = 'epss' and s.kev_listed
           and datediff('day', cast(s.published as date), cast(s.known_from as date)) in (0, 1, 7, 30, 90))
),
set_events as (
    select
        k.cve_id,
        k.known_from as "at",
        k.field as kind,
        k.source,
        case
            -- the API holds a status since the event that set it, so the event does not repeat it
            when k.field = 'nvd_status' then json_object('sets', json_object('nvd_status', k.value))
            when k.vector_prefix is not null then json_object(
                'sets', json_object(
                    k.vector_prefix || '_vector', k.value,
                    k.vector_prefix || '_score', try_cast(sc.score as double),
                    k.vector_prefix || '_band', b.band))
            when k.field = 'kev_listed' then json_object(
                'sets', json_object('kev_date_added',
                    coalesce(strftime(k.kev_date_added, '%Y-%m-%d'), strftime(k.known_from, '%Y-%m-%d'))))
            when k.field = 'kev_ransomware' then json_object('sets', json_object('kev_ransomware', k.value))
            when k.first_exploit then json_object(
                'value', k.value, 'sets', json_object('exploit_first_seen', strftime(k.known_from, '%Y-%m-%d')))
            when k.field in ('exploit_code', 'epss') then json_object('value', k.value)
            when k.field = 'cve_state' then json_object('sets', json_object('state', k.value))
        end as body,
        k.dated_by
    from kept as k
    left join scores as sc
        on sc.cve_id = k.cve_id and sc.vector_field = k.field and sc.source = k.source and sc.known_from = k.known_from
    left join bands as b
        on b.cve_id = k.cve_id and b.vector_field = k.field and b.source = k.source and b.known_from = k.known_from
),
ssvc as (
    -- CISA writes the three decision points together; one event per change, naming what changed.
    select cve_id, known_from as "at", 'ssvc' as kind, source,
        json_object(
            'sets', to_json(map_from_entries(list_filter([
                struct_pack(k := 'ssvc_exploitation', v := max(case when field = 'ssvc_exploitation' then value end)),
                struct_pack(k := 'ssvc_automatable', v := max(case when field = 'ssvc_automatable' then value end)),
                struct_pack(k := 'ssvc_technical_impact', v := max(case when field = 'ssvc_technical_impact' then value end))
            ], lambda x: x.v is not null)))
        ) as body,
        any_value(dated_by) as dated_by
    from series
    where field like 'ssvc_%'
    group by cve_id, known_from, source
),
ended as (
    -- A fact that ended with nothing after it in its series was removed by its source; the fields
    -- it gave are empty from then on.
    select
        f.cve_id,
        f.known_to as "at",
        f.field || '_removed' as kind,
        f.source,
        json_object(
            'previous', f.value,
            'sets', case
                when f.vector_prefix is not null then json_object(
                    f.vector_prefix || '_vector', null, f.vector_prefix || '_score', null, f.vector_prefix || '_band', null)
                when f.field like 'ssvc_%' then json_object(f.field, null)
                when f.field = 'kev_listed' then json_object('kev_date_added', null)
                when f.field = 'kev_ransomware' then json_object('kev_ransomware', null)
            end
        ) as body,
        f.dated_by
    from series as f
    where f.known_to is not null
      and ((f.field in ('cvss31_vector', 'cvss40_vector') and f.vector_prefix is not null)
           or f.field like 'ssvc_%' or f.field in ('kev_listed', 'kev_ransomware'))
      and not exists (
          select 1 from series as n
          where n.cve_id = f.cve_id and n.field = f.field and n.source = f.source and n.known_from = f.known_to
      )
),

-- dated_by says how an event's time was found; it is left out for the NVD's own change history,
-- the usual case, and the API reads its absence that way (unscheduled_api.asof, Event.rule).
select cve_id, "at", kind, source,
    cast(json_merge_patch(body, case when dated_by is null or dated_by = 'nvd_history' then '{{}}'
                                     else json_object('dated_by', dated_by) end) as varchar) as detail_json
from (
    select * from set_events
    union all select * from ssvc
    union all select * from ended
)
where "at" is not null and body is not null
order by cve_id, "at", kind, source, detail_json
"""


def _entry(target: Path, rows: int) -> dict[str, object]:
    return {
        "file": target.name,
        "sha256": sha256_file(target),
        "rows": int(rows),
        "bytes": target.stat().st_size,
    }


def _write_parquet(frame: pl.DataFrame, target: Path) -> dict[str, object]:
    tmp = target.with_name(target.name + ".tmp")
    frame.write_parquet(tmp, compression="zstd", statistics=False)
    tmp.replace(target)
    return _entry(target, frame.height)


def product_frame(root: Path) -> pl.DataFrame:
    """One row per stand in, in the words the console shows, with the pin the rule chose."""
    customer = yaml.safe_load((root / "config" / "customer.yaml").read_text(encoding="utf-8"))
    picks = yaml.safe_load((root / "config" / "products.yaml").read_text(encoding="utf-8"))["stand_ins"]
    by_id = {p["product"]: p for p in picks}
    rows = []
    for product in customer["products"]:
        pick = by_id.get(product["id"], {})
        image = "image" in pick
        rows.append(
            {
                "product_id": product["id"],
                "name": product["name"],
                "what": product.get("what"),
                "ecosystem": product.get("ecosystem"),
                "kind": "image" if image else "repository",
                "stand_in": f"{pick['image']}:{pick['tag']}" if image else pick.get("repository"),
                "repository_url": (
                    f"https://hub.docker.com/_/{str(pick['image']).rsplit('/', 1)[-1]}"
                    if image
                    else pick.get("url") or f"https://github.com/{pick.get('repository')}"
                ),
                "commit": pick.get("digest") if image else pick.get("commit"),
                "pinned_on": str(pick.get("pushed") or pick.get("commit_date") or "")[:10] or None,
                "platform": pick.get("platform") or product.get("platform"),
                "licence": None if image else pick.get("licence"),
                "stars": None if image else pick.get("stars"),
                "read_on": str(pick.get("date_read") or "")[:10] or None,
            }
        )
    return pl.DataFrame(rows).sort("product_id")


def finding_frame(root: Path) -> pl.DataFrame:
    """Every finding of the exposure, at the pin and today, one row each, in a fixed order."""
    rows: list[dict[str, Any]] = []
    for snapshot, name in (("pin", "findings_pin.json"), ("today", "findings_today.json")):
        data = json.loads((root / "results" / "exposure" / name).read_text(encoding="utf-8"))
        for product_id, block in sorted(data["products"].items()):
            for f in block["findings"]:
                matches = f.get("matches") or [{}]
                first = matches[0]
                published = sorted(str(m["published"]) for m in matches if m.get("published"))
                modified = sorted(str(m["modified"]) for m in matches if m.get("modified"))
                key = "|".join([product_id, snapshot, str(f.get("component")), str(f.get("primary_id"))])
                rows.append(
                    {
                        "finding_id": hashlib.sha256(key.encode()).hexdigest()[:32],
                        "product_id": product_id,
                        "snapshot": snapshot,
                        "as_of": block.get("as_of") or f.get("as_of"),
                        "component": f.get("package"),
                        "package": f.get("package"),
                        "binary_package": f.get("binary_package"),
                        "version": f.get("version"),
                        "purl": f.get("purl"),
                        "ecosystem": f.get("ecosystem"),
                        "primary_id": f.get("primary_id"),
                        "advisory_ids": [str(x) for x in f.get("advisory_ids") or []],
                        "cve_aliases": [str(x) for x in f.get("cve_aliases") or []],
                        "upstream_cves": [str(x) for x in f.get("upstream_cves") or []],
                        "matched_range": first.get("matched_range"),
                        "fixed": [str(x) for x in f.get("fixed_versions") or []],
                        "fix_available": bool(f.get("fix_available")),
                        "source": ",".join(
                            first.get("sources") or ([first["source"]] if first.get("source") else [])
                        ),
                        "advisory_known_from": f.get("known_from"),
                        "advisory_known_from_rule": f.get("known_from_rule"),
                        # The first publication and the last change of the advisories matched, the
                        # dates the legacy report prints for a CVE the serving slice does not hold.
                        "advisory_published": published[0] if published else None,
                        "advisory_modified": modified[-1] if modified else None,
                        "summary": f.get("summary"),
                        "severity_json": json.dumps(f.get("severity") or [], sort_keys=True),
                    }
                )
    schema: dict[str, pl.DataType | type[pl.DataType]] = {
        "advisory_ids": pl.List(pl.String),
        "cve_aliases": pl.List(pl.String),
        "upstream_cves": pl.List(pl.String),
        "fixed": pl.List(pl.String),
        "package": pl.String,
        "binary_package": pl.String,
        "advisory_published": pl.String,
        "advisory_modified": pl.String,
    }
    frame = pl.DataFrame(rows, schema_overrides=schema)
    return frame.sort(["product_id", "snapshot", "finding_id"])


def backlog_document(root: Path) -> dict[str, Any]:
    """The Q1 to Q6 charts the console draws, as scripts/backlog_charts.py writes them."""
    path = root / "results" / "backlog" / "charts.json"
    if not path.exists():
        return {"questions": [], "note": "results/backlog/charts.json does not exist yet; run the analysis"}
    doc: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return doc


def locks_summary(root: Path) -> dict[str, Any]:
    """Per source: when its lock was written, how many raw files and rows it holds, its digest."""
    cadence = yaml.safe_load((root / "config" / "sources.yaml").read_text(encoding="utf-8"))["schedules"]
    out: dict[str, Any] = {}
    for path in sorted((root / "data" / "locks").glob("*.lock.json")):
        lock = json.loads(path.read_text(encoding="utf-8"))
        name = path.name.removesuffix(".lock.json")
        entries = lock.get("entries") or []
        out[name] = {
            "updated_at": lock.get("updated_at"),
            "files": len(entries),
            "rows": sum(int(e.get("rows") or 0) for e in entries),
            "lock_sha256": sha256_file(path),
            "cadence": "hourly" if name in cadence.get("hourly", []) else "daily",
        }
    return out


def sources_summary(root: Path, ledger_rows: int = 40) -> dict[str, Any]:
    """The quarantine counts of the lake and the newest rows of the run ledger, for the data page."""
    quarantine_path = root / "results" / "lake" / "quarantine.json"
    quarantine = json.loads(quarantine_path.read_text(encoding="utf-8")) if quarantine_path.exists() else []
    ledger_path = root / "data" / "locks" / "ledger.jsonl"
    ledger = []
    if ledger_path.exists():
        lines = ledger_path.read_text(encoding="utf-8").splitlines()
        ledger = [json.loads(line) for line in lines[-ledger_rows:] if line.strip()]
    return {"quarantine": quarantine, "ledger_recent": ledger}


def check_against_api(out: Path, sample: int = 20_000) -> dict[str, int]:
    """Read the bundle back the way the API's sync reads it, and refuse a bundle the API would refuse.

    The columns of each file against the API's contract (cve.parquet exactly, in its order), the
    first rows of each file through the API's own row builders, and every field a provenance entry
    or an event names against the fields the API serves.
    """
    from unscheduled_api import bundle as api

    served = set(api.CVE_FIELDS)
    checked: dict[str, int] = {}
    for name, table in api.TABLES.items():
        path = out / table.file
        if name in api.OPTIONAL_TABLES and not path.exists():
            continue
        present = api.file_columns(path)
        api.check_columns(name, present)
        if name == "cve" and present != [c.name for c in api.CVE_COLUMNS]:
            raise SystemExit(f"serving: cve.parquet columns differ from the API contract: {present}")
        rows = 0
        for batch in api.iter_rows(path, present, batch=sample):
            for raw in batch:
                row = api.ROW_BUILDERS[name](raw)
                named: set[str] = set()
                if name == "cve":
                    named = set(row["provenance"])
                elif name == "cve_event":
                    sets = row["detail"].get("sets")
                    named = set(sets) if isinstance(sets, dict) else set()
                unknown = named - served
                if unknown:
                    raise SystemExit(
                        f"serving: {table.file} names fields the API does not serve: {sorted(unknown)}"
                    )
                rows += 1
            break
        checked[name] = rows
    return checked


def prediction_files(root: Path, out: Path) -> list[dict[str, object]]:
    """The Phase 2 batch predictions for the CVEs this bundle holds, and the registry export they
    name their models by; none before the first batch is committed (scripts/predict_serving.py)."""
    from unscheduled_api import bundle

    source = root / "models" / "serving" / "predictions.parquet"
    record_path = paths.results_dir() / "models" / "predictions.json"
    registry_path = paths.results_dir() / "registry" / "registry.json"
    if not (source.exists() and record_path.exists() and registry_path.exists()):
        return []
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if sha256_file(source) != record["file"]["sha256"]:
        raise SystemExit("serving: models/serving/predictions.parquet is not the file its record names")
    held = pl.read_parquet(out / "cve.parquet", columns=["cve_id"])
    columns = [c.name for c in bundle.PREDICTION_COLUMNS]
    frame = held.join(pl.read_parquet(source, columns=columns), on="cve_id", how="inner").sort("cve_id")
    entries = [_write_parquet(frame.select(columns), out / bundle.PREDICTION)]
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    document = {
        "batch": record["batch"],
        "made_on": record.get("made_on"),
        "rule": record["rule"],
        "rows_in_batch": record["rows"],
        "survival_model": record["survival_model"],
        "product_model": record["product_model"],
        "models": [
            {
                "name": m["name"],
                "description": m["description"],
                "chosen_by": m.get("chosen_by"),
                "aliases": m["aliases"],
                "versions": [
                    {k: v[k] for k in ("version", "run_name", "role", "stage", "description", "dev", "test")}
                    for v in m["versions"]
                ],
            }
            for m in registry["models"]
        ],
        "registry_archive": registry.get("archive", {}).get("file"),
    }
    target = out / bundle.MODELS
    target.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    entries.append(_entry(target, len(document["models"])))
    return entries


def build(lake_file: Path, out: Path) -> dict[str, object]:
    out.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(lake_file), read_only=True)
    try:
        for setting in ("set TimeZone = 'UTC'", "set threads = 1", "set preserve_insertion_order = true"):
            con.execute(setting).fetchall()
        cut = con.execute("select data_cut from config.lake_build").fetchall()[0][0]
        con.execute(POPULATION).fetchall()
        con.execute(PROVENANCE).fetchall()
        files = []
        for name, sql in (("cve.parquet", CVE), ("cve_event.parquet", EVENTS)):
            target = out / name
            tmp = target.with_name(target.name + ".tmp")
            con.execute(
                f"copy ({sql}) to '{tmp}' (format parquet, compression zstd, row_group_size 100000)"
            ).fetchall()
            tmp.replace(target)
            rows = con.execute(f"select count(*) from read_parquet('{target}')").fetchall()[0][0]
            files.append(
                {
                    "file": name,
                    "sha256": sha256_file(target),
                    "rows": int(rows),
                    "bytes": target.stat().st_size,
                }
            )
    finally:
        con.close()
    root = paths.root()
    files.append(_write_parquet(product_frame(root), out / "product.parquet"))
    files.append(_write_parquet(finding_frame(root), out / "finding.parquet"))
    backlog = out / "backlog.json"
    backlog.write_text(json.dumps(backlog_document(root), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    files.append(_entry(backlog, len(backlog_document(root).get("questions", []))))
    files.extend(prediction_files(root, out))
    lake_report = json.loads((paths.results_dir() / "lake" / "lake.json").read_text(encoding="utf-8"))
    if lake_report.get("sha256") != sha256_file(lake_file):
        raise SystemExit(
            "serving: results/lake/lake.json does not describe the lake file on disk; rebuild the lake"
        )
    manifest = {
        "files": files,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "data_cut": cut.isoformat(),
        "lake_digest": lake_report["sha256"],
        "lake": {"sha256": lake_report["sha256"], "content_digest": lake_report["content_digest"]},
        "locks": locks_summary(root),
        "sources": sources_summary(root),
        "population": "every CVE published since 2021-01-01, rejected excluded, and every KEV listed CVE",
    }
    (out / "bundle_manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    checked = check_against_api(out)
    print(
        "serving: read back with the API's readers: " + ", ".join(f"{k} {v} rows" for k, v in checked.items())
    )
    return manifest


def main() -> int:
    manifest = build(paths.lake_file(), paths.data_dir() / "serving")
    for f in manifest["files"]:  # type: ignore[attr-defined]
        print(f"serving: {f['file']} {f['rows']} rows, {f['bytes'] / 1e6:.1f} MB, {f['sha256'][:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
