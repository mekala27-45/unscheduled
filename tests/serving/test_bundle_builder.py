"""The serving bundle carries every stand in and every finding of the committed exposure, once."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from scripts import build_serving_bundle as bundle

ROOT = Path(__file__).resolve().parents[2]


def test_every_stand_in_is_a_product_with_its_pin() -> None:
    products = bundle.product_frame(ROOT)
    assert products.height == 6
    assert products.get_column("product_id").n_unique() == 6
    assert products.filter(products["commit"].is_null()).height == 0
    assert set(products.get_column("kind")) == {"repository", "image"}


def test_every_finding_of_the_exposure_is_served_once() -> None:
    findings = bundle.finding_frame(ROOT)
    summary = json.loads((ROOT / "results" / "exposure" / "summary.json").read_text(encoding="utf-8"))
    expected = sum(
        p[snapshot]["findings"] for p in summary["products"].values() for snapshot in ("pin", "today")
    )
    assert findings.height == expected
    assert findings.get_column("finding_id").n_unique() == findings.height
    assert set(findings.get_column("snapshot")) == {"pin", "today"}
    assert findings.filter(findings["as_of"].is_null()).height == 0


def test_the_locks_are_summarized_by_source_without_any_secret(tmp_path: Path) -> None:
    # The locks ride in the lake release, not in git, so the test writes two the way the fetcher does.
    (tmp_path / "config").mkdir()
    shutil.copy(ROOT / "config" / "sources.yaml", tmp_path / "config" / "sources.yaml")
    locks_dir = tmp_path / "data" / "locks"
    locks_dir.mkdir(parents=True)
    for name, rows in (("nvd", [2000, 1500]), ("kev", [1484])):
        entries = [
            {"name": f"{name}-{i}", "rows": n, "sha256": "0" * 64, "size": 10, "url": "https://example.org/x"}
            for i, n in enumerate(rows)
        ]
        lock = {"lock_version": 1, "source": name, "updated_at": "2026-11-12T01:00:00Z", "entries": entries}
        (locks_dir / f"{name}.lock.json").write_text(json.dumps(lock), encoding="utf-8")
    locks = bundle.locks_summary(tmp_path)
    assert set(locks) == {"nvd", "kev"}
    assert locks["nvd"]["files"] == 2 and locks["nvd"]["rows"] == 3500 and locks["nvd"]["cadence"] == "daily"
    assert locks["kev"]["cadence"] == "hourly"
    assert all(len(v["lock_sha256"]) == 64 for v in locks.values())
    text = json.dumps(locks)
    assert "postgres" not in text and "token" not in text.lower()


def test_the_scoped_corpus_joins_the_bundle_and_the_api_reads_it_back(tmp_path: Path) -> None:
    """ADR 0011: Neon holds every version of the advisories that name a CVE the products carry, of
    every KEV entry and of every CWE weakness; an advisory for another CVE stays in the lake."""
    import polars as pl
    from unscheduled_core.hashing import sha256_file

    from tests.api.fixtures.bundle import corpus_documents, corpus_frames, write_bundle

    out = tmp_path / "serving"
    write_bundle(out)
    other = {
        **corpus_documents()[0],
        "doc_id": "ghsa:GHSA-zzzz-zzzz-zzzz",
        "cve_ids": ["CVE-2020-12345"],
    }
    cwe = {
        **corpus_documents()[1],
        "doc_id": "cwe:CWE-502",
        "source": "cwe",
        "version": "4.21",
        "cve_ids": [],
    }
    documents, chunks = corpus_frames([*corpus_documents(), other, cwe])
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    documents.write_parquet(corpus_dir / "documents.parquet")
    chunks.with_columns(pl.lit("x").alias("digest")).write_parquet(corpus_dir / "chunks.parquet")
    files = {
        name: {"sha256": sha256_file(corpus_dir / name)} for name in ("documents.parquet", "chunks.parquet")
    }
    (corpus_dir / "manifest.json").write_text(
        json.dumps({"status": "built", "files": files}), encoding="utf-8"
    )

    entries = bundle.add_corpus(out, corpus_dir)
    assert [e["file"] for e in entries] == ["corpus_document.parquet", "corpus_chunk.parquet"]
    kept = pl.read_parquet(out / "corpus_document.parquet")
    assert sorted(kept.get_column("doc_id").to_list()) == [
        "cwe:CWE-502",
        "ghsa:GHSA-fx01-0001-aaaa",
        "kev:CVE-2021-90001",
    ]
    assert pl.read_parquet(out / "corpus_chunk.parquet").get_column("doc_id").n_unique() == 3
    manifest = json.loads((out / "bundle_manifest.json").read_text(encoding="utf-8"))
    named = {f["file"]: f for f in manifest["files"]}
    assert named["corpus_chunk.parquet"]["sha256"] == sha256_file(out / "corpus_chunk.parquet")
    # Again: the same files, the manifest names each once.
    bundle.add_corpus(out, corpus_dir)
    again = json.loads((out / "bundle_manifest.json").read_text(encoding="utf-8"))
    assert [f["file"] for f in again["files"]].count("corpus_document.parquet") == 1


def test_a_corpus_that_waits_adds_nothing(tmp_path: Path) -> None:
    from tests.api.fixtures.bundle import write_bundle

    out = tmp_path / "serving"
    write_bundle(out)
    before = (out / "bundle_manifest.json").read_text(encoding="utf-8")
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "manifest.json").write_text(json.dumps({"status": "waiting"}), encoding="utf-8")
    assert bundle.add_corpus(out, corpus_dir) == []
    assert (out / "bundle_manifest.json").read_text(encoding="utf-8") == before
    assert not (out / "corpus_chunk.parquet").exists()
