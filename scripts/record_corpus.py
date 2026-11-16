"""Record the advisory corpus a lake run published: results/retrieval/corpus.json and its part.

    python scripts/record_corpus.py            # the newest serving release with a corpus
    python scripts/record_corpus.py --release serving-202611161200

Reads the release through the GitHub REST API with the gh command line, downloads the corpus
manifest, checks that every file it lists is in the release under the name of its own digest, and
runs the leakage tests (the planted document over the corpus view and over every index, and the
corpus rebuilt under two hash seeds). The record holds what went in, what was left out and why, the
release with every asset and its sha256, and the outcome of the tests; checklist line 4 reads it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from unscheduled_core.manifest import ManifestBuilder

ROOT = Path(__file__).resolve().parents[1]
REPO = "mekala27-45/unscheduled"
OUT = ROOT / "results" / "retrieval" / "corpus.json"
PART = ROOT / "results" / "parts" / "corpus.json"
LEAKAGE_TESTS = (
    "tests/retrieval/test_corpus.py::test_a_document_planted_after_the_query_time_is_never_returned",
    "tests/retrieval/test_corpus.py::test_the_corpus_has_the_same_digests_under_two_hash_seeds",
    "tests/retrieval/test_search.py::test_a_document_planted_after_the_query_time_is_returned_by_no_index",
)
NAMES = {
    "chunks.parquet": "corpus-{digest}.parquet",
    "queries.parquet": "corpus-queries-{digest}.parquet",
}


def gh_json(path: str) -> Any:
    done = subprocess.run(["gh", "api", path], capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def asset_bytes(asset_id: int) -> bytes:
    done = subprocess.run(
        ["gh", "api", "-H", "Accept: application/octet-stream", f"repos/{REPO}/releases/assets/{asset_id}"],
        capture_output=True,
        check=True,
    )
    return done.stdout


def find_release(tag: str | None) -> dict[str, Any]:
    releases = gh_json(f"repos/{REPO}/releases?per_page=60")
    for release in releases:
        if tag and release["tag_name"] != tag:
            continue
        if any(a["name"].startswith("corpus-manifest-") for a in release["assets"]):
            return dict(release)
    raise SystemExit(f"record: no release {'named ' + tag if tag else ''} holds a corpus yet")


def leakage() -> dict[str, Any]:
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *LEAKAGE_TESTS],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    last = (done.stdout.strip().splitlines() or [""])[-1]
    passed = re.search(r"(\d+) passed", last)
    return {
        "tests": list(LEAKAGE_TESTS),
        "passed": int(passed.group(1)) if passed else 0,
        "summary": last,
        "result": "pass" if done.returncode == 0 and "skipped" not in last else "fail",
    }


def record(release: dict[str, Any]) -> dict[str, Any]:
    assets = {a["name"]: a for a in release["assets"] if a["name"].startswith("corpus-")}
    manifest_asset = next(a for name, a in assets.items() if name.startswith("corpus-manifest-"))
    raw = asset_bytes(int(manifest_asset["id"]))
    manifest = json.loads(raw)
    published: dict[str, str] = {}
    for file, pattern in NAMES.items():
        digest = manifest["files"][file]["sha256"]
        name = pattern.format(digest=digest[:12])
        if name not in assets:
            raise SystemExit(f"record: {release['tag_name']} has no {name} for {file}")
        if int(assets[name]["size"]) != int(manifest["files"][file]["bytes"]):
            raise SystemExit(f"record: {name} is not the size the manifest gives")
        published[name] = digest
    manifest_digest = hashlib.sha256(raw).hexdigest()
    if manifest_asset["name"] != f"corpus-manifest-{manifest_digest[:12]}.json":
        raise SystemExit(f"record: {manifest_asset['name']} is not named by its own digest")
    published[manifest_asset["name"]] = manifest_digest
    checks = leakage()
    return {
        "phase": 3,
        "status": manifest["status"],
        "built_at": manifest.get("built_at"),
        "code": manifest.get("code"),
        "lake_data_cut": manifest.get("lake_data_cut"),
        "content_digest": manifest["content_digest"],
        "tokenizer": manifest["tokenizer"],
        "max_tokens": manifest["max_tokens"],
        "bronze": manifest["bronze"],
        "scope": manifest["scope"],
        "documents": manifest["documents"],
        "chunks": manifest["chunks"],
        "queries": manifest["queries"],
        "files": manifest["files"],
        "published": {"tag": release["tag_name"], "release_id": release["id"], "assets": published},
        "leakage": checks,
        "result": "pass" if manifest["status"] == "built" and checks["result"] == "pass" else "fail",
    }


def part(rec: dict[str, Any]) -> dict[str, Any]:
    m = ManifestBuilder(str(rec["built_at"])[:10])
    population = f"the corpus {rec['content_digest'][:12]} published with {rec['published']['tag']}"
    docs, chunks, queries = rec["documents"], rec["chunks"], rec["queries"]
    values: list[tuple[str, Any, str]] = [
        ("corpus.chunks", chunks["total"], "int"),
        ("corpus.advisory_documents", docs["advisories"]["documents"], "int"),
        ("corpus.advisory_versions", docs["advisories"]["versions"], "int"),
        ("corpus.advisory_versions_without_text", docs["advisories"]["versions_without_text"], "int"),
        ("corpus.kev_documents", docs["kev"]["documents"], "int"),
        ("corpus.kev_texts", docs["kev"]["texts"], "int"),
        ("corpus.kev_edited", docs["kev"]["edited"], "int"),
        ("corpus.kev_read_from_listing", docs["kev"]["first_text_read_from_listing"], "int"),
        ("corpus.cwe_documents", docs["cwe"]["documents"], "int"),
        ("corpus.cwe_texts", docs["cwe"]["texts"], "int"),
        ("corpus.cwe_catalogs", docs["cwe"]["catalog_versions"], "int"),
        ("corpus.scope_cves", rec["scope"]["cves"], "int"),
        ("corpus.product_cves", rec["scope"]["product_cves"], "int"),
    ]
    for window in ("development", "shadow"):
        q = queries[window]
        values += [
            (f"corpus.{window}.published", q["published"], "int"),
            (f"corpus.{window}.queries", q["queries"], "int"),
            (f"corpus.{window}.no_description", q["left_out"].get("no_description_at_day0", 0), "int"),
            (f"corpus.{window}.no_document", q["left_out"].get("no_advisory_or_kev_at_day0", 0), "int"),
            (f"corpus.{window}.with_kev", q["with_kev"], "int"),
            (f"corpus.{window}.relevant_per_query", q["relevant_per_query"], "float2"),
        ]
    for key, value, fmt in values:
        m.value(key, value, fmt, origin="scripts/record_corpus.py", population=population, source="build")
    return m.dump()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--release", default=None)
    args = parser.parse_args(argv)
    rec = record(find_release(args.release))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rec, indent=1, default=str) + "\n", encoding="utf-8")
    PART.write_text(json.dumps(part(rec), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"record: {rec['published']['tag']}, {rec['chunks']['total']} chunks, leakage {rec['leakage']['result']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
