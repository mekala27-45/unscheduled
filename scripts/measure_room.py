"""Measure the room in Neon before Phase 3 spends any of it: step 2 and ADR 0011.

Only the API can reach Neon, so what Neon holds now is read from /health. Everything else is measured
on a Postgres with pgvector that is not Neon, and the script refuses a Neon address:

1. the replica: the newest serving bundle loaded into a fresh schema by the sync's own loader, with
   the code as it stands, so each table's size without bloat and with the event key of the plan;
2. the churn: two daily bundles compared row by row with the sync's own digests, the rows a day
   adds and changes;
3. the corpus sample: chunks cut from raw advisory files, the KEV catalog and the CWE catalog, with
   the text, a full text index, a halfvec(384) column and an HNSW index, sized per chunk;
4. the checkpoints: the fixture graph of unscheduled_agent.room run to its approval interrupt;
5. the projection: the database on 13 December under the plan, against the ceiling.

The vectors of the sample are random unit vectors from a fixed seed: the size of a halfvec column and
of an HNSW graph depends on the number of vectors, their dimension and m, not on their values.

    uv run python scripts/measure_room.py --database-url URL --bundle DIR --bundle-tag TAG \\
        --previous DIR --previous-tag TAG --advisories DIR --advisories-commit SHA --kev FILE --cwe FILE [--write]
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import duckdb
import httpx
import numpy as np
import psycopg
import pyarrow.parquet as pq
import sqlalchemy as sa
from unscheduled_agent import room as checkpoint_room
from unscheduled_api import bundle as bnd
from unscheduled_api import migrate
from unscheduled_api.db import make_engine
from unscheduled_api.settings import Settings
from unscheduled_api.sync import Sync
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_retrieval.chunks import Chunk, chunk_document
from unscheduled_retrieval.documents import from_cwe, from_kev, from_osv
from unscheduled_retrieval.tokenizer import counter, fetch_tokenizer
from unscheduled_sources.cwe import text_rows

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "agent" / "room.json"
PART = ROOT / "results" / "parts" / "room.json"
API = "https://unscheduled-api.vercel.app"
REPLICA = "room_replica"
SAMPLE = "room_sample"
UNTIL = date(2026, 12, 13)
SAMPLE_CHUNKS = {"ghsa": 700, "kev": 150, "cwe": 150}
SEED = 7
DIM = 384
HNSW = {"m": 16, "ef_construction": 64}
# The run store, capped by the retention rule of the plan: runs waiting for a person keep every
# checkpoint; a decided run keeps its latest for 30 days, then only its record in the runs tables.
WAITING_CAP = 100
DECIDED_CAP = 500
RUN_RECORD_BYTES = 12_000
# Autovacuum reclaims a table's dead rows once they pass this share of its rows (migration 0004).
VACUUM_SCALE = 0.02
PLAN_LIMIT_NOTE = "1 GB a project on the Neon free plan (its FAQ, updated 3 November 2026)"


def _mb(n: float) -> float:
    return round(n / 1_000_000, 1)


def _sizes(conn: sa.Connection, schema: str) -> dict[str, dict[str, int]]:
    rows = conn.execute(
        sa.text(
            "select c.relname as name, pg_total_relation_size(c.oid) as total, "
            "pg_indexes_size(c.oid) as indexes, c.reltuples::bigint as rows "
            "from pg_class c join pg_namespace n on n.oid = c.relnamespace "
            "where n.nspname = :s and c.relkind = 'r' order by total desc"
        ),
        {"s": schema},
    )
    return {
        str(r.name): {"total_bytes": int(r.total), "index_bytes": int(r.indexes), "rows": max(int(r.rows), 0)}
        for r in rows
    }


def replica(url: str, bundle_dir: Path, cache: Path) -> dict[str, Any]:
    """The serving tables as a fresh load leaves them, through the sync's own loader."""
    settings = Settings.from_env(
        {
            "UNSCHED_CORS_ORIGINS": "http://localhost",
            "UNSCHED_CACHE_DIR": str(cache),
            "UNSCHED_MIGRATE_ON_START": "0",
            "UNSCHED_DB_SCHEMA": REPLICA,
        },
        database_url=url,
    )
    plain = sa.create_engine(url)
    with plain.begin() as conn:
        conn.execute(sa.text(f'drop schema if exists "{REPLICA}" cascade'))
    plain.dispose()
    failed = migrate.upgrade(settings)
    if failed is not None:
        raise RuntimeError(f"the replica did not migrate: {failed}")
    engine = make_engine(url, REPLICA)
    sync = Sync(engine, settings, None)  # type: ignore[arg-type]
    sync.ceiling = 10**13  # the replica is sized, not budgeted
    loaded: dict[str, int] = {}
    for table in ("product", "cve", "cve_event", "finding", "prediction"):
        path = bundle_dir / bnd.TABLES[table].file
        total = bnd.file_rows(path)
        for offset in range(0, total, bnd.TABLES[table].chunk_rows):
            with engine.begin() as conn:
                sync._load(conn, table, path, offset)
        loaded[table] = total
    with engine.begin() as conn:
        # The end of a load, as the sync ends one: the oversized event key index is rebuilt.
        rebuilt = sync._rebuild(conn, loaded)
    with engine.connect() as conn:
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")
        conn.execute(sa.text("vacuum analyze"))
        sizes = _sizes(conn, REPLICA)
        server = str(conn.execute(sa.text("show server_version")).scalar())
        vector = conn.execute(
            sa.text("select extversion from pg_extension where extname = 'vector'")
        ).scalar()
        column = conn.execute(
            sa.text(f'select coalesce(sum(pg_column_size(event_id)), 0) from "{REPLICA}".cve_event')
        ).scalar()
        levers = {
            str(r.lever): {"rows": int(r.n), "row_bytes": int(r.bytes)}
            for r in conn.execute(sa.text(LEVERS.format(s=REPLICA)))
        }
    engine.dispose()
    return {
        "server_version": server,
        "pgvector": str(vector) if vector else None,
        "rows_loaded": loaded,
        "rebuilt_indexes": rebuilt,
        "tables": sizes,
        "event_key_column_bytes": int(column or 0),
        "next_levers": levers,
    }


# The room the next trims would free, kept for when the readings say the plan needs more: the
# predictions of development and test CVEs the NVD scored (the Phase 2 prompt allowed serving only the
# CVEs without an NVD analysis and the evaluation sample), and the events of CVEs published before
# 2024 that no stand in product carries and KEV does not list. Row bytes only, without their indexes.
LEVERS = """
select 'predictions of scored development and test CVEs' as lever, count(*) as n,
       coalesce(sum(pg_column_size(p.*)), 0) as bytes
from "{s}".prediction p join "{s}".cve c using (cve_id)
where c.published >= '2024-01-01' and c.published < '2026-04-01' and c.nvd_cvss31_band is not null
union all
select 'events of CVEs before 2024 outside the products and KEV', count(*), coalesce(sum(pg_column_size(e.*)), 0)
from "{s}".cve_event e join "{s}".cve c using (cve_id)
where c.published < '2024-01-01' and c.kev_date_added is null
  and not exists (select 1 from "{s}".finding f where c.cve_id = any(f.cve_ids))
"""


def churn(previous: Path, newest: Path, tags: tuple[str, str]) -> dict[str, Any]:
    """What a day of the lake adds and changes, read with the sync's own row digests."""

    def manifest(folder: Path) -> dict[str, Any]:
        return dict(json.loads((folder / bnd.MANIFEST).read_text(encoding="utf-8")))

    def digests(folder: Path) -> dict[str, str]:
        return {
            str(r["cve_id"]): bnd.cve_row(r)["row_digest"]
            for r in pq.read_table(folder / "cve.parquet").to_pylist()
        }

    before, after = digests(previous), digests(newest)
    changed = sum(1 for k, v in after.items() if k in before and before[k] != v)
    events_before = pq.read_metadata(previous / "cve_event.parquet").num_rows
    events_after = pq.read_metadata(newest / "cve_event.parquet").num_rows
    first, second = manifest(previous), manifest(newest)
    t0 = datetime.fromisoformat(str(first["generated_at"]).replace("Z", "+00:00"))
    t1 = datetime.fromisoformat(str(second["generated_at"]).replace("Z", "+00:00"))
    days = (t1 - t0).total_seconds() / 86_400
    return {
        "previous": {"tag": tags[0], "generated_at": first["generated_at"]},
        "newest": {"tag": tags[1], "generated_at": second["generated_at"]},
        "days": round(days, 3),
        "cve_new": len(set(after) - set(before)),
        "cve_gone": len(set(before) - set(after)),
        "cve_changed": changed,
        "events_new": events_after - events_before,
    }


def sample_documents(advisories: Path, kev: Path, cwe: Path) -> dict[str, list[Any]]:
    """The documents the sample is cut from, in a fixed order: advisory files sorted by path, the
    KEV entries and the CWE weaknesses in the order their catalogs list them."""
    docs: dict[str, list[Any]] = {"ghsa": [], "kev": [], "cwe": []}
    for path in sorted(advisories.rglob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        known = str(record.get("modified") or record.get("published"))
        docs["ghsa"].append(from_osv(record, source="ghsa", known_from=known))
    catalog = json.loads(kev.read_text(encoding="utf-8"))
    for entry in catalog["vulnerabilities"]:
        docs["kev"].append(
            from_kev(
                entry,
                catalog_version=str(catalog["catalogVersion"]),
                known_from=f"{entry['dateAdded']}T00:00:00Z",
            )
        )
    with zipfile.ZipFile(cwe) as archive:
        info, entries = text_rows(archive.read(archive.namelist()[0]))
    for entry in entries:
        docs["cwe"].append(
            from_cwe(
                entry, catalog_version=info.get("Version", ""), known_from=f"{info.get('Date')}T00:00:00Z"
            )
        )
    return docs


def corpus_sample(url: str, docs: dict[str, list[Any]], count: Any) -> dict[str, Any]:
    """The sample chunks in the table shape step 4 builds, sized per chunk and per component."""
    picked: list[Chunk] = []
    per_source: dict[str, dict[str, int]] = {}
    for source, wanted in SAMPLE_CHUNKS.items():
        taken: list[Chunk] = []
        used = 0
        for doc in docs[source]:
            if len(taken) >= wanted:
                break
            taken.extend(chunk_document(doc, count))
            used += 1
        per_source[source] = {"documents": used, "chunks": len(taken)}
        picked.extend(taken)
    rng = np.random.default_rng(SEED)
    vectors = rng.standard_normal((len(picked), DIM))
    vectors /= np.linalg.norm(vectors, axis=1, keepdims=True)
    used_docs = [
        d for source in SAMPLE_CHUNKS for d in docs[source] if any(c.doc_id == d.doc_id for c in picked)
    ]
    plain = url.replace("postgresql+psycopg://", "postgresql://", 1)
    with psycopg.connect(plain, autocommit=True) as conn:
        conn.execute("create extension if not exists vector")
        conn.execute(f'drop schema if exists "{SAMPLE}" cascade')
        conn.execute(f'create schema "{SAMPLE}"')
        # The shapes step 4 builds: a document row with what is not chunked, and its chunks with
        # the spans of their sections, a vector, and a full text index on an expression rather than
        # a stored tsvector column.
        conn.execute(
            f'create table "{SAMPLE}".document (doc_id text primary key, source text not null, '
            "version text not null, known_from timestamptz not null, cve_ids text[] not null, "
            "refs jsonb not null)"
        )
        conn.execute(
            f'create table "{SAMPLE}".chunk (chunk_id text primary key, doc_id text not null, '
            "source text not null, ordinal int not null, known_from timestamptz not null, "
            f"digest text not null, spans jsonb not null, text text not null, embedding halfvec({DIM}) not null)"
        )
        with (
            conn.cursor() as cur,
            cur.copy(
                f'copy "{SAMPLE}".document (doc_id, source, version, known_from, cve_ids, refs) from stdin'
            ) as copy,
        ):
            for doc in used_docs:
                refs: list[str] = next(
                    (s.text.splitlines() for s in doc.sections if s.name == "references"), []
                )
                copy.write_row(
                    (doc.doc_id, doc.source, doc.version, doc.known_from, list(doc.cve_ids), json.dumps(refs))
                )
        with (
            conn.cursor() as cur,
            cur.copy(
                f'copy "{SAMPLE}".chunk (chunk_id, doc_id, source, ordinal, known_from, digest, spans, text, embedding) '
                "from stdin"
            ) as copy,
        ):
            for chunk, vector in zip(picked, vectors, strict=True):
                copy.write_row(
                    (
                        chunk.chunk_id,
                        chunk.doc_id,
                        chunk.source,
                        chunk.ordinal,
                        chunk.known_from,
                        chunk.digest,
                        json.dumps([[s.section, s.start, s.end] for s in chunk.spans]),
                        chunk.text,
                        "[" + ",".join(f"{x:.5f}" for x in vector) + "]",
                    )
                )
        conn.execute(
            f"create index chunk_text on \"{SAMPLE}\".chunk using gin (to_tsvector('english', text))"
        )
        conn.execute(
            f'create index chunk_hnsw on "{SAMPLE}".chunk using hnsw (embedding halfvec_cosine_ops) '
            f"with (m = {HNSW['m']}, ef_construction = {HNSW['ef_construction']})"
        )
        conn.execute(f'create index chunk_known on "{SAMPLE}".chunk (known_from, doc_id)')
        conn.execute(f'vacuum analyze "{SAMPLE}".chunk')
        conn.execute(f'vacuum analyze "{SAMPLE}".document')
        heap = int(conn.execute(f"select pg_table_size('\"{SAMPLE}\".chunk')").fetchone()[0])  # type: ignore[index]
        documents = int(conn.execute(f"select pg_total_relation_size('\"{SAMPLE}\".document')").fetchone()[0])  # type: ignore[index]
        index = {
            name: int(size)
            for name, size in conn.execute(
                "select indexrelname, pg_relation_size(indexrelid) from pg_stat_user_indexes "
                "where schemaname = %s and relname = 'chunk'",
                (SAMPLE,),
            ).fetchall()
        }
        columns = conn.execute(
            f"select avg(pg_column_size(text)), avg(pg_column_size(to_tsvector('english', text))), "
            f'avg(pg_column_size(embedding)), avg(octet_length(text)) from "{SAMPLE}".chunk'
        ).fetchone()
        by_source = {
            str(s): (int(n), float(b))
            for s, n, b in conn.execute(
                f'select source, count(*), avg(pg_column_size(c.*)) from "{SAMPLE}".chunk c group by 1'
            ).fetchall()
        }
        found = conn.execute("select extversion from pg_extension where extname = 'vector'").fetchone()
        version = str(found[0]) if found else "none"
    n = len(picked)
    total = heap + sum(index.values())
    tokens = [c.tokens for c in picked]
    assert columns is not None
    return {
        "chunks": n,
        "per_source": {
            s: {
                **v,
                "chunks_per_document": round(v["chunks"] / v["documents"], 3),
                "row_bytes": round(by_source[s][1]),
            }
            for s, v in per_source.items()
        },
        "tokens": {"max": max(tokens), "mean": round(sum(tokens) / n, 1), "limit": 256},
        "pgvector": version,
        "hnsw": HNSW,
        "heap_bytes": heap,
        "index_bytes": index,
        "bytes_per_chunk": round(total / n),
        "documents": len(used_docs),
        "document_bytes_per_document": round(documents / max(len(used_docs), 1)),
        "heap_bytes_per_chunk": round(heap / n),
        "index_bytes_per_chunk": {k: round(v / n) for k, v in index.items()},
        "column_bytes_mean": {
            "text": round(float(columns[0])),
            "tsvector_if_stored": round(float(columns[1])),
            "embedding": round(float(columns[2])),
            "text_octets": round(float(columns[3])),
        },
        "vectors": f"random unit vectors, seed {SEED}",
    }


def neon_scope(root: Path) -> dict[str, int]:
    """The documents Neon would hold: the advisories that name a CVE the six stand in products carry,
    every KEV entry and every CWE weakness, counted in the lake."""
    con = duckdb.connect(str(root / "data" / "lake" / "unscheduled.duckdb"), read_only=True)
    findings = str(root / "data" / "serving" / "finding.parquet")
    con.execute(
        "create temp table prod as select distinct c as cve_id from (select unnest(list_concat("
        f"coalesce(cve_aliases, []), coalesce(upstream_cves, []))) as c from read_parquet('{findings}')) "
        "where c like 'CVE-%'"
    )
    advisories = con.execute(
        "select count(distinct advisory_id) from (select advisory_id, unnest(cve_ids) as cve_id "
        "from silver.advisory_versions) where cve_id in (select cve_id from prod)"
    ).fetchone()
    cves = con.execute("select count(*) from prod").fetchone()
    con.close()
    return {"product_cves": int(cves[0]), "advisories": int(advisories[0])}  # type: ignore[index]


def neon_now() -> dict[str, Any]:
    response = httpx.get(f"{API}/health", timeout=60)
    response.raise_for_status()
    body = response.json()
    db = body["database"]
    return {
        "read_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "data_version": body.get("data_version"),
        "migration": db.get("migration"),
        "server_version": db.get("server_version"),
        "pgvector_version": db.get("pgvector_version"),
        "database_size_bytes": int(db["database_size_bytes"]),
        "storage_ceiling_bytes": int(db["storage_ceiling_bytes"]),
        "storage_share_used": db.get("storage_share_used"),
        "tables": {
            t["name"]: {k: t[k] for k in ("total_bytes", "index_bytes", "rows_estimate")}
            for t in db["tables"]
        },
    }


def project(
    now: dict[str, Any],
    rep: dict[str, Any],
    day: dict[str, Any],
    sample: dict[str, Any],
    scope: dict[str, Any],
    ckpt: dict[str, Any],
) -> dict[str, Any]:
    """The database on 13 December under the plan."""
    tables = rep["tables"]
    neon = now["tables"]
    freed = neon["cve_event"]["total_bytes"] - tables["cve_event"]["total_bytes"]
    after = now["database_size_bytes"] - freed
    cve_row = tables["cve"]["total_bytes"] / max(tables["cve"]["rows"], 1)
    event_row = tables["cve_event"]["total_bytes"] / max(tables["cve_event"]["rows"], 1)
    per_day = (day["cve_new"] * cve_row + day["events_new"] * event_row) / day["days"]
    dead_rows = 50 + VACUUM_SCALE * tables["cve"]["rows"]
    bloat_bound = dead_rows * cve_row
    read_on = datetime.fromisoformat(now["read_at"].replace("Z", "+00:00")).date()
    days = (UNTIL - read_on).days
    chunks = {
        "ghsa": round(scope["advisories"] * sample["per_source"]["ghsa"]["chunks_per_document"]),
        "kev": round(scope["kev_entries"] * sample["per_source"]["kev"]["chunks_per_document"]),
        "cwe": round(scope["cwe_weaknesses"] * sample["per_source"]["cwe"]["chunks_per_document"]),
    }
    documents = scope["advisories"] + scope["kev_entries"] + scope["cwe_weaknesses"]
    corpus = (
        sum(chunks.values()) * sample["bytes_per_chunk"] + documents * sample["document_bytes_per_document"]
    )
    runs = (
        WAITING_CAP * ckpt["waiting"]["bytes_per_run"]
        + DECIDED_CAP * ckpt["keep_latest"]["bytes_per_run"]
        + (WAITING_CAP + DECIDED_CAP) * RUN_RECORD_BYTES
    )
    projected = after + per_day * days + bloat_bound + corpus + runs
    ceiling = now["storage_ceiling_bytes"]
    return {
        "freed_by_event_key_bytes": freed,
        "after_plan_bytes": after,
        "growth_bytes_per_day": round(per_day),
        "days": days,
        "until": UNTIL.isoformat(),
        "growth_bytes": round(per_day * days),
        "dead_rows_bound": round(dead_rows),
        "bloat_bound_bytes": round(bloat_bound),
        "corpus_chunks": chunks,
        "corpus_bytes": round(corpus),
        "run_store": {
            "waiting_cap": WAITING_CAP,
            "decided_cap": DECIDED_CAP,
            "record_bytes_per_run": RUN_RECORD_BYTES,
            "bytes": round(runs),
        },
        "projected_bytes": round(projected),
        "projected_share": round(projected / ceiling, 4),
        "margin_bytes": round(ceiling - projected),
    }


def manifest_part(record: dict[str, Any]) -> dict[str, Any]:
    m = ManifestBuilder(record["measured_at"][:10])
    now, rep, day, sample, proj, ckpt = (
        record["neon_now"],
        record["replica"],
        record["churn"],
        record["sample"],
        record["projection"],
        record["checkpoints"],
    )
    neon_pop = f"Neon as the API read it at {now['read_at']}, holding {now['data_version']}"
    rep_pop = f"a fresh load of {day['newest']['tag']} on Postgres {rep['server_version']} with pgvector {rep['pgvector']}"
    values: list[tuple[str, Any, str, str, str]] = [
        ("room.neon.size_mb", _mb(now["database_size_bytes"]), "float1", neon_pop, "live"),
        ("room.neon.share", now["storage_share_used"], "pct1", neon_pop, "live"),
        ("room.neon.ceiling_mb", _mb(now["storage_ceiling_bytes"]), "float1", neon_pop, "live"),
    ]
    for table in ("cve_event", "cve", "prediction"):
        values.append(
            (f"room.neon.{table}_mb", _mb(now["tables"][table]["total_bytes"]), "float1", neon_pop, "live")
        )
        values.append(
            (f"room.replica.{table}_mb", _mb(rep["tables"][table]["total_bytes"]), "float1", rep_pop, "build")
        )
        values.append(
            (
                f"room.replica.{table}_index_mb",
                _mb(rep["tables"][table]["index_bytes"]),
                "float1",
                rep_pop,
                "build",
            )
        )
    values += [
        ("room.replica.event_rows", rep["tables"]["cve_event"]["rows"], "int", rep_pop, "build"),
        (
            "room.freed_mb",
            _mb(proj["freed_by_event_key_bytes"]),
            "float1",
            "Neon now less the replica's event table",
            "build",
        ),
        (
            "room.after_mb",
            _mb(proj["after_plan_bytes"]),
            "float1",
            "Neon once the event table is loaded again",
            "build",
        ),
        (
            "room.churn.days",
            day["days"],
            "float2",
            f"{day['previous']['tag']} to {day['newest']['tag']}",
            "build",
        ),
        (
            "room.churn.cve_new",
            day["cve_new"],
            "int",
            f"{day['previous']['tag']} to {day['newest']['tag']}",
            "build",
        ),
        (
            "room.churn.cve_changed",
            day["cve_changed"],
            "int",
            f"{day['previous']['tag']} to {day['newest']['tag']}",
            "build",
        ),
        (
            "room.churn.events_new",
            day["events_new"],
            "int",
            f"{day['previous']['tag']} to {day['newest']['tag']}",
            "build",
        ),
        (
            "room.growth_mb_per_day",
            round(proj["growth_bytes_per_day"] / 1_000_000, 2),
            "float2",
            "new rows a day at the replica's bytes a row",
            "build",
        ),
        (
            "room.bloat_bound_mb",
            _mb(proj["bloat_bound_bytes"]),
            "float1",
            "dead CVE rows autovacuum lets wait at the scale of migration 0004",
            "build",
        ),
        ("room.sample.chunks", sample["chunks"], "int", "the corpus sample", "build"),
        (
            "room.sample.bytes_per_chunk",
            sample["bytes_per_chunk"],
            "int",
            "the corpus sample with its three indexes",
            "build",
        ),
        (
            "room.corpus_chunks",
            sum(proj["corpus_chunks"].values()),
            "int",
            "the Neon scope of the corpus",
            "build",
        ),
        ("room.corpus_mb", _mb(proj["corpus_bytes"]), "float1", "the Neon scope of the corpus", "build"),
        (
            "room.checkpoint_kb_waiting",
            round(ckpt["waiting"]["bytes_per_run"] / 1000, 1),
            "float1",
            "the fixture run waiting for a person",
            "build",
        ),
        (
            "room.checkpoint_kb_kept",
            round(ckpt["keep_latest"]["bytes_per_run"] / 1000, 1),
            "float1",
            "the fixture run after keep_latest",
            "build",
        ),
        (
            "room.run_store_mb",
            _mb(proj["run_store"]["bytes"]),
            "float1",
            "the run store at its caps",
            "build",
        ),
        (
            "room.projected_mb",
            _mb(proj["projected_bytes"]),
            "float1",
            f"the database on {proj['until']} under the plan",
            "build",
        ),
        (
            "room.projected_share",
            proj["projected_share"],
            "pct1",
            f"the database on {proj['until']} under the plan",
            "build",
        ),
        (
            "room.margin_mb",
            _mb(proj["margin_bytes"]),
            "float1",
            f"the ceiling less the projection for {proj['until']}",
            "build",
        ),
        ("room.result", record["result"], "text", "the room plan against the ceiling", "build"),
    ]
    later = record.get("neon_after")
    if later:
        after_pop = f"Neon as the API read it at {later['read_at']}, holding {later['data_version']}"
        values += [
            ("room.neon_after.size_mb", _mb(later["database_size_bytes"]), "float1", after_pop, "live"),
            ("room.neon_after.share", later["storage_share_used"], "pct1", after_pop, "live"),
            (
                "room.neon_after.cve_event_mb",
                _mb(later["tables"]["cve_event"]["total_bytes"]),
                "float1",
                after_pop,
                "live",
            ),
            ("room.neon_after.result", later["result"], "text", after_pop, "live"),
        ]
    levers = rep["next_levers"]
    predictions = levers["predictions of scored development and test CVEs"]
    events = levers["events of CVEs before 2024 outside the products and KEV"]
    values += [
        ("room.lever.predictions_rows", predictions["rows"], "int", rep_pop, "build"),
        ("room.lever.predictions_mb", _mb(predictions["row_bytes"]), "float1", rep_pop, "build"),
        ("room.lever.events_rows", events["rows"], "int", rep_pop, "build"),
        ("room.lever.events_mb", _mb(events["row_bytes"]), "float1", rep_pop, "build"),
        (
            "room.corpus_advisories",
            record["scope"]["advisories"],
            "int",
            "advisories that name a CVE the six products carry",
            "lake",
        ),
        ("room.corpus_kev", record["scope"]["kev_entries"], "int", "the KEV catalog", "source:kev"),
        ("room.corpus_cwe", record["scope"]["cwe_weaknesses"], "int", "the CWE catalog", "source:cwe"),
        (
            "room.run_waiting_cap",
            proj["run_store"]["waiting_cap"],
            "int",
            "the retention rule of the plan",
            "static",
        ),
        (
            "room.run_decided_cap",
            proj["run_store"]["decided_cap"],
            "int",
            "the retention rule of the plan",
            "static",
        ),
        (
            "room.rebuilt_pk_mb",
            _mb(rep["rebuilt_indexes"]["cve_event_pkey"]["after_bytes"]),
            "float1",
            rep_pop,
            "build",
        ),
        (
            "room.unbuilt_pk_mb",
            _mb(rep["rebuilt_indexes"]["cve_event_pkey"]["before_bytes"]),
            "float1",
            rep_pop,
            "build",
        ),
    ]
    for key, value, fmt, population, source in values:
        m.value(key, value, fmt, origin="scripts/measure_room.py", population=population, source=source)
    return m.dump()


def after(write: bool) -> int:
    """Neon once the plan is deployed: the head migration, the events loaded again and the room the
    plan said it would free. The record keeps its result only if Neon holds no more than the
    projection said it would after the plan, with one percent for the days between."""
    record = json.loads(OUT.read_text(encoding="utf-8"))
    response = httpx.get(f"{API}/health", timeout=60)
    response.raise_for_status()
    body = response.json()
    db = body["database"]
    counts = (body.get("data") or {}).get("counts") or {}
    tables = {t["name"]: t for t in db["tables"]}
    expected = record["replica"]["rows_loaded"]["cve_event"]
    reading = {
        "read_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "data_version": body.get("data_version"),
        "migration": db.get("migration"),
        "database_size_bytes": int(db["database_size_bytes"]),
        "storage_share_used": db.get("storage_share_used"),
        "events_loaded": int(counts.get("cve_event", 0)),
        "tables": {
            n: {k: t[k] for k in ("total_bytes", "index_bytes", "rows_estimate")} for n, t in tables.items()
        },
    }
    planned = int(record["projection"]["after_plan_bytes"])
    ok = (
        reading["migration"] == "0004"
        and reading["events_loaded"] >= expected
        and reading["database_size_bytes"] <= planned * 1.01
    )
    reading["planned_bytes"] = planned
    reading["result"] = "pass" if ok else "fail"
    record["neon_after"] = reading
    record["result"] = "pass" if ok and record["projection"]["margin_bytes"] > 0 else "fail"
    if write:
        OUT.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
        PART.write_text(json.dumps(manifest_part(record), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"room after: {_mb(reading['database_size_bytes'])} MB with {reading['events_loaded']} events at "
        f"migration {reading['migration']}, planned {_mb(planned)} MB ({reading['result']})"
    )
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--bundle", type=Path, default=None)
    parser.add_argument("--bundle-tag", default=None)
    parser.add_argument("--previous", type=Path, default=None)
    parser.add_argument("--previous-tag", default=None)
    parser.add_argument("--advisories", type=Path, default=None)
    parser.add_argument("--advisories-commit", default=None)
    parser.add_argument("--kev", type=Path, default=None)
    parser.add_argument("--cwe", type=Path, default=None)
    parser.add_argument("--cache", type=Path, default=ROOT / "data" / "cache" / "room")
    parser.add_argument("--write", action="store_true")
    parser.add_argument(
        "--after",
        action="store_true",
        help="read Neon once the plan is deployed and the sync has loaded the events again",
    )
    args = parser.parse_args(argv)
    if args.after:
        return after(args.write)
    missing = [
        k
        for k in (
            "database_url",
            "bundle",
            "bundle_tag",
            "previous",
            "previous_tag",
            "advisories",
            "advisories_commit",
            "kev",
            "cwe",
        )
        if getattr(args, k) is None
    ]
    if missing:
        parser.error("the measure needs " + ", ".join("--" + m.replace("_", "-") for m in missing))
    if "neon.tech" in args.database_url:
        raise SystemExit("measure_room measures on a Postgres that is not Neon; nothing is created in Neon")
    now = neon_now()
    # First, before the replica: a connection the migration leaves open holds a snapshot that would
    # keep VACUUM FULL from reclaiming the checkpoints the retention rule deletes.
    ckpt = checkpoint_room.measure(args.database_url)
    rep = replica(args.database_url, args.bundle, args.cache)
    day = churn(args.previous, args.bundle, (args.previous_tag, args.bundle_tag))
    pinned = fetch_tokenizer(ROOT)
    docs = sample_documents(args.advisories, args.kev, args.cwe)
    sample = corpus_sample(args.database_url, docs, counter(pinned.load()))
    sample["tokenizer"] = {"model": pinned.model_id, "revision": pinned.revision, "sha256": pinned.sha256}
    scope = {**neon_scope(ROOT), "kev_entries": len(docs["kev"]), "cwe_weaknesses": len(docs["cwe"])}
    proj = project(now, rep, day, sample, scope, ckpt)
    record: dict[str, Any] = {
        "measured_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ceiling_bytes": now["storage_ceiling_bytes"],
        "plan_limit": PLAN_LIMIT_NOTE,
        "neon_now": now,
        "replica": rep,
        "churn": day,
        "sample": sample,
        "scope": scope,
        "checkpoints": ckpt,
        "projection": proj,
        "sources": {
            "advisories": (
                f"the {len(docs['ghsa'])} GitHub reviewed advisories that name a CVE the six stand in products "
                f"carry, from github/advisory-database at {args.advisories_commit}"
            ),
            "kev": "the KEV catalog from cisagov/kev-data",
            "cwe": "the CWE catalog from cwe.mitre.org",
        },
    }
    record["result"] = "pass" if proj["margin_bytes"] > 0 else "fail"
    text = json.dumps(record, indent=1, sort_keys=False) + "\n"
    if args.write:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text, encoding="utf-8")
        PART.write_text(json.dumps(manifest_part(record), indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"room: wrote {OUT.relative_to(ROOT)} and {PART.relative_to(ROOT)}")
    print(
        f"room: Neon {_mb(now['database_size_bytes'])} MB now; the event key frees "
        f"{_mb(proj['freed_by_event_key_bytes'])} MB; projected {_mb(proj['projected_bytes'])} MB on "
        f"{proj['until']} ({record['result']})"
    )
    return 0 if record["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
