"""The advisory corpus point in time, and the retrieval queries labelled from the data.

Everything is read from the work database of the lake build (scripts/build_lake.py --keep-work): it
holds a view over every bronze table beside the lake's own tables, so each version is dated by the
rules the lake and the matcher already use, and nothing here dates a fact a second way.

- An advisory version is dated by silver.advisory_versions: from its modified time, and a GitHub
  advisory never before the first commit that carried it. Its words come from osv_text or ghsa_text
  under the same key. The OSV copy of a GitHub advisory is left to the GitHub record, and a version
  whose text was never captured is left out and counted. A withdrawn advisory stops being
  searchable from its withdrawal.
- A KEV entry is dated by kev_text: each distinct text from the first commit that held it. The
  history of kev-data starts on 27 January 2025, so the earliest text of an entry listed before its
  first capture is read from the listing (silver.kev_events.listed_at), which data/PROVENANCE.md
  records as a limit. The ransomware flag changes over time and is a typed fact, not corpus text.
  An entry the lake has never seen in a catalog (removed before the lake began) is left out.
- A CWE weakness is dated by cwe_text: each distinct text from the end of the date of the first
  catalog version that holds it.

The scope is the plan's: the advisories whose aliases name a published CVE of the development or
shadow window, or a CVE the six stand in products carry; every KEV entry; every CWE weakness.

Queries are the published CVEs of the development and shadow windows, each as of day 0, the end of
its publication day in UTC. The query is the description of the CVE List record as the as-of engine
gives it at day 0, over facts dated by the lake's record rule (intermediate.int_cve_versions); the
relevant documents are the advisories whose newest version known at day 0 names the CVE and is not
withdrawn, its KEV entry when listed by then, and the CWE weaknesses of the filer CWEs of that same
record. A CVE is left out, and counted per window, when its description was not yet known at day 0
or when no advisory and no KEV entry was.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

import duckdb
import polars as pl
from unscheduled_core.hashing import canonical_json, sha256_text

from unscheduled_retrieval.chunks import MAX_TOKENS, Chunk, chunk_document
from unscheduled_retrieval.documents import Document, from_cwe, from_kev, from_osv

WINDOWS = ("development", "shadow")
TEXT_TABLES = ("osv_text", "ghsa_text", "kev_text", "cwe_text")
DESCRIPTION_FACTS = "corpus_description_fact"

# A function that answers what the as-of engine answers: the facts current at a time for some CVEs.
AsOf = Callable[[Sequence[str], date], pl.DataFrame]

CHUNK_SCHEMA: dict[str, Any] = {
    "chunk_id": pl.String,
    "doc_id": pl.String,
    "source": pl.String,
    "version": pl.String,
    "known_from": pl.Datetime("us", "UTC"),
    "known_to": pl.Datetime("us", "UTC"),
    "withdrawn": pl.Datetime("us", "UTC"),
    "cve_ids": pl.List(pl.String),
    "ordinal": pl.Int32,
    "sections": pl.List(pl.String),
    "spans_json": pl.String,
    "text": pl.String,
    "tokens": pl.Int32,
    "digest": pl.String,
}
QUERY_SCHEMA: dict[str, Any] = {
    "cve_id": pl.String,
    "window": pl.String,
    "day0": pl.Datetime("us", "UTC"),
    "query": pl.String,
    "relevant": pl.List(pl.String),
    "relevant_advisories": pl.List(pl.String),
    "relevant_kev": pl.List(pl.String),
    "relevant_cwe": pl.List(pl.String),
}


def end_of_day(day: date) -> datetime:
    """The last moment of a day in UTC, the time a day stands for (the as-of engine's rule)."""
    return datetime.combine(day, time(23, 59, 59, 999999), tzinfo=UTC)


def iso(t: datetime | None) -> str:
    return "" if t is None else t.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass
class Version:
    """One version of one document with the moments it became known and, for an advisory, withdrawn."""

    doc: Document
    known_from: datetime
    withdrawn: datetime | None = None


@dataclass
class Corpus:
    versions: list[Version]
    counts: dict[str, Any] = field(default_factory=dict)


def _frame(con: duckdb.DuckDBPyConnection, sql: str, params: Any = None) -> pl.DataFrame:
    out: pl.DataFrame = con.sql(sql, params=params).pl()
    return out


def connect(work_db: str) -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(work_db, read_only=True)
    con.execute("set TimeZone = 'UTC'")
    return con


def missing_text(con: duckdb.DuckDBPyConnection) -> list[str]:
    """The text tables with no rows yet: the corpus waits for their first fetch."""
    return [t for t in TEXT_TABLES if int(con.execute(f"select count(*) from bronze.{t}").fetchone()[0]) == 0]  # type: ignore[index]


def scope_cves(con: duckdb.DuckDBPyConnection, product_cves: Iterable[str]) -> list[str]:
    windows = con.execute(
        "select cve_id from intermediate.int_cve_spine where state = 'PUBLISHED' "
        "and split_window in ('development', 'shadow')"
    ).fetchall()
    return sorted({r[0] for r in windows} | {c for c in product_cves if c.startswith("CVE-")})


ADVISORY_SQL = """
with scope as (select unnest($scope)::varchar as cve_id),
named as (
    select distinct database, advisory_id, ecosystem, modified
    from (
        select database, advisory_id, ecosystem, modified, unnest(cve_ids) as cve_id
        from silver.advisory_versions
        where not (database = 'osv' and source_db = 'GHSA')
    ) as v
    join scope using (cve_id)
)
select
    v.database, v.advisory_id, v.ecosystem, v.aliases, v.published, v.modified, v.withdrawn,
    v.affected_json, v.known_from,
    case when v.database = 'osv' then o.summary else g.summary end as summary,
    case when v.database = 'osv' then t.details else g.details end as details,
    case when v.database = 'osv' then t.references_json else g.references_json end as references_json,
    (t.id is not null or g.ghsa_id is not null) as has_text
from silver.advisory_versions as v
join named as n
    on n.database = v.database and n.advisory_id = v.advisory_id
   and n.ecosystem is not distinct from v.ecosystem and n.modified is not distinct from v.modified
left join bronze.osv_text as t
    on v.database = 'osv' and t.id = v.advisory_id and t.ecosystem = v.ecosystem
   and t.modified is not distinct from v.modified
left join bronze.osv_advisories as o
    on v.database = 'osv' and o.id = v.advisory_id and o.ecosystem = v.ecosystem
   and o.modified is not distinct from v.modified
left join bronze.ghsa_text as g
    on v.database = 'ghsa' and g.ghsa_id = v.advisory_id and g.modified is not distinct from v.modified
order by v.database, v.advisory_id, v.ecosystem, v.known_from, v.modified
"""


def _json(value: str | None) -> Any:
    return json.loads(value) if value else []


def advisories(con: duckdb.DuckDBPyConnection, scope: Sequence[str]) -> Corpus:
    rows = _frame(con, ADVISORY_SQL, {"scope": list(scope)})
    versions: list[Version] = []
    without_text = 0
    seen: set[tuple[str, str]] = set()
    for r in rows.iter_rows(named=True):
        if not r["has_text"]:
            without_text += 1
            continue
        record = {
            "id": r["advisory_id"],
            "modified": iso(r["modified"]) or None,
            "published": iso(r["published"]) or None,
            "aliases": r["aliases"] or [],
            "summary": r["summary"],
            "details": r["details"],
            "affected": _json(r["affected_json"]),
            "references": _json(r["references_json"]),
        }
        doc = from_osv(record, source=r["database"], known_from=iso(r["known_from"]))
        if (doc.doc_id, doc.version) in seen:
            continue
        seen.add((doc.doc_id, doc.version))
        versions.append(Version(doc, r["known_from"], r["withdrawn"]))
    docs = {v.doc.doc_id for v in versions}
    counts = {
        "versions_in_scope": rows.height,
        "versions_without_text": without_text,
        "versions": len(versions),
        "documents": len(docs),
        "by_database": dict(sorted(Counter(v.doc.source for v in versions).items())),
    }
    return Corpus(versions, counts)


KEV_SQL = """
with texts as (
    select
        t.*, k.listed_at, k.vendor_project, k.product,
        row_number() over (partition by t.cve_id order by t.captured_at, t.text_digest) as nth
    from bronze.kev_text as t
    left join silver.kev_events as k using (cve_id)
)
select
    *,
    case when nth = 1 and listed_at is not null then least(listed_at, captured_at)
         else captured_at end as known_from
from texts
order by cve_id, captured_at, text_digest
"""


def kev(con: duckdb.DuckDBPyConnection) -> Corpus:
    rows = _frame(con, KEV_SQL)
    versions: list[Version] = []
    removed: set[str] = set()
    backdated: set[str] = set()
    for r in rows.iter_rows(named=True):
        if r["listed_at"] is None:
            removed.add(r["cve_id"])
            continue
        entry = {
            "cveID": r["cve_id"],
            "vendorProject": r["vendor_project"],
            "product": r["product"],
            "vulnerabilityName": r["vulnerability_name"],
            "dateAdded": r["date_added"].isoformat() if r["date_added"] else None,
            "shortDescription": r["short_description"],
            "requiredAction": r["required_action"],
            "notes": r["notes"],
        }
        doc = from_kev(entry, catalog_version=r["text_digest"], known_from=iso(r["known_from"]))
        # Listed more than a day before the first capture: the history did not reach the listing.
        if r["captured_at"] - r["known_from"] > timedelta(days=1):
            backdated.add(r["cve_id"])
        versions.append(Version(doc, r["known_from"]))
    counts = {
        "texts": len(versions),
        "documents": len({v.doc.doc_id for v in versions}),
        "edited": sum(1 for n in Counter(v.doc.doc_id for v in versions).values() if n > 1),
        "first_text_read_from_listing": len(backdated),
        "never_in_a_lake_catalog": len(removed),
    }
    return Corpus(versions, counts)


CWE_SQL = """
with texts as (
    select
        *,
        sha256(concat_ws(chr(31), coalesce(name, ''), coalesce(description, ''),
            coalesce(extended_description, ''), coalesce(consequences, ''), coalesce(mitigations, '')))
            as text_digest,
        list_transform(string_split(catalog_version, '.'), lambda x: try_cast(x as integer)) as version_key
    from bronze.cwe_text
),
ordered as (
    select *, lag(text_digest) over (partition by cwe_id order by catalog_date, version_key) as previous
    from texts
)
select * from ordered
where previous is null or previous <> text_digest
order by cwe_id, catalog_date, version_key
"""


def cwe(con: duckdb.DuckDBPyConnection) -> Corpus:
    rows = _frame(con, CWE_SQL)
    versions: list[Version] = []
    for r in rows.iter_rows(named=True):
        known = end_of_day(r["catalog_date"])
        doc = from_cwe(r, catalog_version=str(r["catalog_version"]), known_from=iso(known))
        versions.append(Version(doc, known))
    catalogs = con.execute("select count(distinct catalog_version) from bronze.cwe_text").fetchone()
    counts = {
        "catalog_versions": int(catalogs[0]) if catalogs else 0,
        "texts": len(versions),
        "documents": len({v.doc.doc_id for v in versions}),
    }
    return Corpus(versions, counts)


ORDER = ["doc_id", "known_from", "version"]


def _ends(versions: Sequence[Version]) -> pl.DataFrame:
    """When each version stopped being current: the moment the next version of its document became
    known, over every version, so a version without chunks still ends the one before it."""
    frame = pl.DataFrame(
        [{"doc_id": v.doc.doc_id, "known_from": v.known_from, "version": v.doc.version} for v in versions],
        schema={"doc_id": pl.String, "known_from": pl.Datetime("us", "UTC"), "version": pl.String},
    )
    return (
        frame.unique().sort(ORDER).with_columns(pl.col("known_from").shift(-1).over("doc_id").alias("ends"))
    )


def chunk_frame(
    versions: Iterable[Version], count: Callable[[str], int], max_tokens: int = MAX_TOKENS
) -> pl.DataFrame:
    """Every chunk of every version. A version is current from its known_from until the next version
    of its document is known, so a search reads the view at a time as one condition on each row."""
    listed = list(versions)
    rows: list[dict[str, Any]] = []
    for v in listed:
        for c in chunk_document(v.doc, count, max_tokens):
            rows.append(_chunk_row(v, c))
    frame = pl.DataFrame(rows, schema=CHUNK_SCHEMA)
    frame = frame.drop("known_to").join(_ends(listed), on=ORDER, how="left").rename({"ends": "known_to"})
    return frame.select(list(CHUNK_SCHEMA)).sort([*ORDER, "ordinal"])


DOCUMENT_SCHEMA: dict[str, Any] = {
    "doc_id": pl.String,
    "source": pl.String,
    "version": pl.String,
    "known_from": pl.Datetime("us", "UTC"),
    "known_to": pl.Datetime("us", "UTC"),
    "withdrawn": pl.Datetime("us", "UTC"),
    "cve_ids": pl.List(pl.String),
    "sections_json": pl.String,
}


def document_frame(versions: Iterable[Version]) -> pl.DataFrame:
    """Every version with all its sections, the ones no search reads included (the references of an
    advisory, the notes of a KEV entry), for the verifier to check a citation against."""
    listed = list(versions)
    rows = [
        {
            "doc_id": v.doc.doc_id,
            "source": v.doc.source,
            "version": v.doc.version,
            "known_from": v.known_from,
            "withdrawn": v.withdrawn,
            "cve_ids": list(v.doc.cve_ids),
            "sections_json": canonical_json([[s.name, s.text] for s in v.doc.sections]),
        }
        for v in listed
    ]
    schema = {k: t for k, t in DOCUMENT_SCHEMA.items() if k != "known_to"}
    frame = (
        pl.DataFrame(rows, schema=schema)
        .join(_ends(listed), on=ORDER, how="left")
        .rename({"ends": "known_to"})
    )
    return frame.select(list(DOCUMENT_SCHEMA)).unique(ORDER, keep="first").sort(ORDER)


def _chunk_row(v: Version, c: Chunk) -> dict[str, Any]:
    return {
        "chunk_id": c.chunk_id,
        "doc_id": c.doc_id,
        "source": c.source,
        "version": v.doc.version,
        "known_from": v.known_from,
        "known_to": None,
        "withdrawn": v.withdrawn,
        "cve_ids": list(v.doc.cve_ids),
        "ordinal": c.ordinal,
        "sections": list(c.sections),
        "spans_json": canonical_json([[s.section, s.start, s.end] for s in c.spans]),
        "text": c.text,
        "tokens": c.tokens,
        "digest": c.digest,
    }


VISIBLE_SQL = (
    "known_from <= {t} and (known_to is null or known_to > {t}) and (withdrawn is null or withdrawn > {t})"
)


def visible(at: datetime) -> pl.Expr:
    """A chunk a search may read at a time: its version is the newest of its document known by then,
    and that version had not been withdrawn by then. VISIBLE_SQL is the same condition in SQL."""
    return (
        (pl.col("known_from") <= at)
        & (pl.col("known_to").is_null() | (pl.col("known_to") > at))
        & (pl.col("withdrawn").is_null() | (pl.col("withdrawn") > at))
    )


def as_of(chunks: pl.DataFrame, at: datetime) -> pl.DataFrame:
    """The chunks a search may read at a time. Every index is built from this condition."""
    return chunks.filter(visible(at)).sort(["doc_id", "ordinal"])


def description_facts(con: duckdb.DuckDBPyConnection) -> None:
    """The description and the filer CWEs of every CVE List record version as facts in the shape the
    as-of engine reads, dated by the lake's record rule, each current until the next version."""
    con.execute(
        f"""
        create or replace temp table {DESCRIPTION_FACTS} as
        with versions as (
            select
                cve_id, version_no, dated_at, dated_by, description,
                to_json(coalesce(problem_cwes, []::varchar[]))::varchar as problem_cwes,
                lead(dated_at) over (partition by cve_id order by dated_at, version_no) as known_to
            from intermediate.int_cve_versions
            where upper(state) = 'PUBLISHED'
        )
        select cve_id, 'description' as field, 'cvelist' as source, description as value,
               dated_at as known_from, known_to, dated_by
        from versions where description is not null and description <> ''
        union all
        select cve_id, 'problem_cwes', 'cvelist', problem_cwes, dated_at, known_to, dated_by
        from versions
        """
    )


def query_population(con: duckdb.DuckDBPyConnection) -> pl.DataFrame:
    return _frame(
        con,
        "select cve_id, split_window as window, cast(published as date) as published_day "
        "from intermediate.int_cve_spine where state = 'PUBLISHED' "
        "and split_window in ('development', 'shadow') order by cve_id",
    )


def query_texts(population: pl.DataFrame, asof: AsOf) -> pl.DataFrame:
    """The description and filer CWEs of each CVE as the as-of engine gives them at day 0."""
    out: list[dict[str, Any]] = []
    for (day,), group in population.group_by("published_day", maintain_order=True):
        ids = group.get_column("cve_id").to_list()
        facts = asof(ids, day)
        values: dict[tuple[str, str], str] = {}
        for f in facts.iter_rows(named=True):
            if f["field"] in ("description", "problem_cwes"):
                values[(f["cve_id"], f["field"])] = f["value"]
        for r in group.iter_rows(named=True):
            cwes = values.get((r["cve_id"], "problem_cwes"))
            out.append(
                {
                    "cve_id": r["cve_id"],
                    "window": r["window"],
                    "day0": end_of_day(day),
                    "query": values.get((r["cve_id"], "description")),
                    "filer_cwes": json.loads(cwes) if cwes else [],
                }
            )
    schema: dict[str, Any] = {
        "cve_id": pl.String,
        "window": pl.String,
        "day0": pl.Datetime("us", "UTC"),
        "query": pl.String,
        "filer_cwes": pl.List(pl.String),
    }
    return pl.DataFrame(out, schema=schema).sort("cve_id")


def documents_frame(chunks: pl.DataFrame) -> pl.DataFrame:
    return chunks.select("doc_id", "source", "version", "known_from", "withdrawn", "cve_ids").unique(
        ["doc_id", "version", "known_from"]
    )


def label(queries: pl.DataFrame, chunks: pl.DataFrame) -> tuple[pl.DataFrame, dict[str, Any]]:
    """The relevant documents of every query, and the queries left out with the reason, per window."""
    docs = documents_frame(chunks)
    con = duckdb.connect()
    con.execute("set TimeZone = 'UTC'")
    con.register("q", queries.to_arrow())
    con.register("d", docs.to_arrow())
    pairs = _frame(
        con,
        """
        with named as (
            select distinct q.cve_id, q.day0, d.doc_id, d.source
            from q join (select doc_id, source, unnest(cve_ids) as cve_id from d where source <> 'cwe') as d
              using (cve_id)
        ),
        newest as (
            select n.cve_id, n.doc_id, n.source,
                   arg_max(d.cve_ids, d.known_from) as cve_ids,
                   arg_max(d.withdrawn, d.known_from) as withdrawn,
                   n.day0
            from named as n join d on d.doc_id = n.doc_id and d.known_from <= n.day0
            group by n.cve_id, n.doc_id, n.source, n.day0
        ),
        cwe_known as (
            select distinct q.cve_id, d.doc_id
            from (select cve_id, day0, unnest(filer_cwes) as cwe_id from q) as q
            join d on d.source = 'cwe' and d.doc_id = 'cwe:' || q.cwe_id and d.known_from <= q.day0
        )
        select cve_id, doc_id, source from newest
        where list_contains(cve_ids, cve_id) and (withdrawn is null or withdrawn > day0)
        union all
        select cve_id, doc_id, 'cwe' from cwe_known
        """,
    )
    con.close()
    grouped: dict[str, dict[str, list[str]]] = {}
    for r in pairs.sort(["cve_id", "source", "doc_id"]).iter_rows(named=True):
        grouped.setdefault(r["cve_id"], {}).setdefault(r["source"], []).append(r["doc_id"])
    rows: list[dict[str, Any]] = []
    left_out: dict[str, Counter[str]] = {w: Counter() for w in WINDOWS}
    for r in queries.iter_rows(named=True):
        found = grouped.get(r["cve_id"], {})
        advisories_found = found.get("ghsa", []) + found.get("osv", [])
        kev_found = found.get("kev", [])
        if not r["query"]:
            left_out[r["window"]]["no_description_at_day0"] += 1
            continue
        if not advisories_found and not kev_found:
            left_out[r["window"]]["no_advisory_or_kev_at_day0"] += 1
            continue
        cwe_found = found.get("cwe", [])
        rows.append(
            {
                "cve_id": r["cve_id"],
                "window": r["window"],
                "day0": r["day0"],
                "query": r["query"],
                "relevant": sorted(advisories_found + kev_found + cwe_found),
                "relevant_advisories": sorted(advisories_found),
                "relevant_kev": kev_found,
                "relevant_cwe": cwe_found,
            }
        )
    labelled = pl.DataFrame(rows, schema=QUERY_SCHEMA).sort(["window", "cve_id"])
    summary: dict[str, Any] = {}
    for w in WINDOWS:
        kept = labelled.filter(pl.col("window") == w)
        summary[w] = {
            "published": int(queries.filter(pl.col("window") == w).height),
            "queries": kept.height,
            "left_out": dict(sorted(left_out[w].items())),
            "with_kev": int(kept.filter(pl.col("relevant_kev").list.len() > 0).height),
            "with_cwe": int(kept.filter(pl.col("relevant_cwe").list.len() > 0).height),
            "relevant_per_query": _mean(kept.get_column("relevant").list.len()),
        }
    return labelled, summary


def _mean(values: pl.Series) -> float:
    mean = values.mean() if values.len() else None
    return round(float(mean), 3) if isinstance(mean, int | float) else 0.0


def content_digest(chunks: pl.DataFrame) -> str:
    """A digest of what the corpus says and when each part became known, independent of file encoding."""
    lines = (
        chunks.select(
            pl.concat_str(
                [
                    pl.col("chunk_id"),
                    pl.col("doc_id"),
                    pl.col("version"),
                    pl.col("known_from").dt.to_string("%Y-%m-%dT%H:%M:%S%.6f"),
                    pl.col("known_to").dt.to_string("%Y-%m-%dT%H:%M:%S%.6f").fill_null(""),
                    pl.col("withdrawn").dt.to_string("%Y-%m-%dT%H:%M:%S%.6f").fill_null(""),
                    pl.col("digest"),
                ],
                separator="\t",
            ).alias("line")
        )
        .sort("line")
        .get_column("line")
        .to_list()
    )
    return sha256_text("\n".join(lines))
