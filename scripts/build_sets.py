"""Build the point in time training sets of Phase 2 from the lake and its bronze.

    uv run python scripts/build_sets.py [--out data/sets]

Reads data/lake/unscheduled.duckdb with the NVD change history and the CVE List records in
data/bronze, writes one inputs file and one labels file per split to data/sets (never committed),
and commits what describes them: results/models/sets.json (rows, label coverage, feature coverage
and the exact content digest of every file, with the lake digests and the lake release they came
from) and the manifest part results/parts/models.json. The test labels sit in a file of their own
that only scripts/score_test.py opens.

    uv run python scripts/build_sets.py --check

rebuilds the sets and compares the content digest of every file with results/models/sets.json,
writing nothing that is committed: the models workflow runs it before it fits anything, so a model
is fit on the committed sets or not at all.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from unscheduled_core.manifest import ManifestBuilder
from unscheduled_models import sets

ORIGIN = "scripts/build_sets.py"


def lake_identity() -> dict[str, Any]:
    lake = json.loads((ROOT / "results" / "lake" / "lake.json").read_text(encoding="utf-8"))
    release_file = ROOT / "results" / "lake" / "release.json"
    release = json.loads(release_file.read_text(encoding="utf-8")) if release_file.exists() else {}
    return {
        "lake_sha256": lake["sha256"],
        "lake_content_digest": lake["content_digest"],
        "lake_release": release.get("tag"),
    }


def manifest_part(record: dict[str, Any]) -> dict[str, Any]:
    m = ManifestBuilder(str(record["lake_cut"])[:10])
    population = "published CVEs, rejected excluded, by the window of their publication date"
    for split, cov in record["coverage"].items():
        for key in (
            "rows",
            "with_band",
            "with_metrics",
            "with_cwe",
            "kev_180",
            "kev_q03",
            "description_from_history",
        ):
            m.value(
                f"models.sets.{split}.{key}",
                int(cov[key]),
                "int",
                origin=ORIGIN,
                population=f"{population}: {split}",
                source="models",
            )
        for feature, value in cov["feature_share"].items():
            m.value(
                f"models.sets.{split}.share.{feature}",
                float(value),
                "pct1",
                origin=ORIGIN,
                population=f"{population}: {split}, share of rows with the feature known at day 0",
                source="models",
            )
    rows = [
        [
            split,
            int(cov["rows"]),
            int(cov["with_band"]),
            int(cov["kev_180"]),
            float(cov["feature_share"]["filer_band"]),
            float(cov["feature_share"]["description"]),
        ]
        for split, cov in record["coverage"].items()
    ]
    m.table(
        "models.sets.coverage",
        ["Window", "CVEs", "NVD band", "KEV within 180 days", "Filer band at day 0", "Description"],
        ["text", "int", "int", "int", "pct1", "pct1"],
        rows,
        origin=ORIGIN,
        population=population,
        source="models",
    )
    m.value(
        "models.sets.cwe_classes",
        len(record["cwe_classes"]),
        "int",
        origin=ORIGIN,
        population="the CWE classes of the label: the most frequent in train, and other",
        source="models",
    )
    return m.dump()


def check(record: dict[str, Any]) -> int:
    """Every rebuilt file against the committed record: the same files, the same content digests."""
    committed = json.loads((ROOT / "results" / "models" / "sets.json").read_text(encoding="utf-8"))["files"]
    built = {name: entry["content_digest"] for name, entry in record["files"].items()}
    expected = {name: entry["content_digest"] for name, entry in committed.items()}
    differ = sorted(name for name in expected.keys() | built.keys() if built.get(name) != expected.get(name))
    if differ:
        print("sets: differ from results/models/sets.json: " + ", ".join(differ))
        return 1
    print(f"sets: all {len(built)} files match results/models/sets.json")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "data" / "sets")
    parser.add_argument(
        "--check", action="store_true", help="compare with results/models/sets.json, write no result"
    )
    args = parser.parse_args(argv)
    started = time.monotonic()
    record = sets.build(ROOT / "data" / "lake" / "unscheduled.duckdb", ROOT / "data" / "bronze", args.out)
    if args.check:
        return check(record)
    record.update(lake_identity())
    record["seconds"] = round(time.monotonic() - started, 1)
    out = ROOT / "results" / "models" / "sets.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    part = ROOT / "results" / "parts" / "models.json"
    part.write_text(json.dumps(manifest_part(record), indent=1) + "\n", encoding="utf-8")
    for split, cov in record["coverage"].items():
        print(
            f"sets: {split} {cov['rows']} rows, {cov['with_band']} with an NVD band, {cov['kev_180']} KEV within 180 days"
        )
    print(f"sets: wrote {len(record['files'])} files in {record['seconds']}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
