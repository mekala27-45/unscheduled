"""Build the advisory corpus point in time from the lake build's work database (ADR 0011, step 4).

    python scripts/build_lake.py --keep-work      # the work database, with bronze and the lake
    python scripts/build_serving_bundle.py        # the findings name the CVEs the products carry
    python scripts/build_corpus.py                # data/corpus: chunks, queries, manifest

Writes data/corpus/chunks.parquet (every chunk of every document version with the moment it became
known), data/corpus/queries.parquet (the development and shadow queries with their relevant
documents) and data/corpus/manifest.json (what went in, what was left out and why, the files with
their digests). Tokens are counted with the tokenizer of the embedding model config/models.yaml
pins. While a text table has no rows yet the corpus waits: the manifest says so and the script exits
0, so the lake workflow goes on. scripts/publish_serving.py --corpus then sends the files by digest.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import polars as pl
from unscheduled_core.hashing import sha256_file
from unscheduled_lake.engine import Engine
from unscheduled_retrieval import corpus
from unscheduled_retrieval.chunks import MAX_TOKENS
from unscheduled_retrieval.tokenizer import counter, fetch_tokenizer

ROOT = Path(__file__).resolve().parents[1]
WORK_DB = ROOT / "data" / "cache" / "lake" / "unscheduled.duckdb"
FINDINGS = ROOT / "data" / "serving" / "finding.parquet"
OUT = ROOT / "data" / "corpus"


def product_cves(findings: Path) -> list[str]:
    """Every CVE a finding of the six stand in products names, as an alias or an upstream CVE."""
    frame = pl.read_parquet(findings)
    cves: set[str] = set()
    for column in ("cve_aliases", "upstream_cves"):
        if column in frame.columns:
            cves.update(c for values in frame.get_column(column).drop_nulls().to_list() for c in values)
    return sorted(c for c in cves if c.startswith("CVE-"))


def write(frame: pl.DataFrame, path: Path) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.write_parquet(path, compression="zstd", compression_level=9, statistics=True)
    return {"sha256": sha256_file(path), "bytes": path.stat().st_size, "rows": frame.height}


def build(
    work_db: Path,
    findings: Path,
    out: Path,
    count: Any,
    tokenizer: dict[str, str],
) -> dict[str, Any]:
    con = corpus.connect(str(work_db))
    manifest: dict[str, Any] = {"phase": 3, "tokenizer": tokenizer, "max_tokens": MAX_TOKENS}
    cut = con.execute("select data_cut from config.lake_build").fetchone()
    manifest["lake_data_cut"] = str(cut[0]) if cut else None
    manifest["bronze"] = {
        name: {"files": files, "rows": rows}
        for name, files, rows in con.execute(
            "select name, files, rows from config.bronze_tables "
            "where name in ('osv_advisories', 'osv_text', 'ghsa', 'ghsa_text', 'kev', 'kev_text', "
            "'cwe_text', 'cve_records') order by name"
        ).fetchall()
    }
    waiting = corpus.missing_text(con)
    if waiting:
        manifest["status"] = "waiting"
        manifest["waiting_for"] = waiting
        con.close()
        return manifest

    products = product_cves(findings)
    scope = corpus.scope_cves(con, products)
    adv = corpus.advisories(con, scope)
    kev = corpus.kev(con)
    cwe = corpus.cwe(con)
    chunks = corpus.chunk_frame([*adv.versions, *kev.versions, *cwe.versions], count)

    corpus.description_facts(con)
    engine = Engine(con, facts=corpus.DESCRIPTION_FACTS)
    population = corpus.query_population(con)
    texts = corpus.query_texts(population, lambda ids, day: engine.asof(ids, day))
    queries, summary = corpus.label(texts, chunks)
    con.close()

    files = {"chunks.parquet": write(chunks, out / "chunks.parquet")}
    files["queries.parquet"] = write(queries, out / "queries.parquet")
    by_source = chunks.group_by("source").agg(
        pl.len().alias("chunks"),
        pl.col("doc_id").n_unique().alias("documents"),
        pl.col("tokens").sum().alias("tokens"),
        pl.col("tokens").max().alias("max_tokens"),
    )
    manifest.update(
        {
            "status": "built",
            "scope": {"product_cves": len(products), "cves": len(scope)},
            "documents": {"advisories": adv.counts, "kev": kev.counts, "cwe": cwe.counts},
            "chunks": {
                "total": chunks.height,
                "by_source": {
                    r["source"]: {k: int(v) for k, v in r.items() if k != "source"}
                    for r in by_source.sort("source").iter_rows(named=True)
                },
                "over_limit": int(chunks.filter(pl.col("tokens") > MAX_TOKENS).height),
            },
            "queries": summary,
            "content_digest": corpus.content_digest(chunks),
            "files": files,
        }
    )
    return manifest


def code_version() -> str | None:
    done = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
    return done.stdout.strip() or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--work", type=Path, default=WORK_DB, help="the work database of the lake build")
    parser.add_argument(
        "--findings", type=Path, default=FINDINGS, help="finding.parquet of the serving bundle"
    )
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args(argv)
    if not args.work.exists():
        raise SystemExit(f"corpus: {args.work} does not exist; run scripts/build_lake.py --keep-work first")
    pinned = fetch_tokenizer(ROOT)
    tokenizer = {"model": pinned.model_id, "revision": pinned.revision, "sha256": pinned.sha256}
    manifest = build(args.work, args.findings, args.out, counter(pinned.load()), tokenizer)
    manifest["code"] = code_version()
    manifest["built_at"] = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "manifest.json").write_text(
        json.dumps(manifest, indent=1, default=str) + "\n", encoding="utf-8"
    )
    if manifest["status"] != "built":
        print(f"corpus: waiting for the first rows of {', '.join(manifest['waiting_for'])}")
        return 0
    print(
        f"corpus: {manifest['chunks']['total']} chunks, digest {manifest['content_digest'][:12]}; "
        + "; ".join(f"{w} {s['queries']} queries of {s['published']}" for w, s in manifest["queries"].items())
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
