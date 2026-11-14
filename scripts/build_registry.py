"""Write the model registry from the committed run records, pack it, and export what it holds.

    uv run python scripts/build_registry.py [--store data/registry/store]
    uv run python scripts/build_registry.py --check     # the export matches the committed records

Reads results/models/{floors,fallback,rank,survival,product}.json, config/operating_points.yaml when
it exists and results/models/test_scoring.json when it exists (unscheduled_models.registry). Writes
the MLflow SQLite store to --store (never committed), packs it into
results/registry/registry-<digest>.tar.gz, and commits results/registry/registry.json, the export the
API and the console read, with the manifest part results/parts/registry.json. A record not committed
yet leaves its candidates out, and the export names it. --check rebuilds the plan of versions from
the records and fails if the committed export disagrees on a version, a stage, a parameter or a
metric; run ids and the archive digest are left out of the comparison, since a rebuild draws new
run ids.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from unscheduled_core.manifest import ManifestBuilder
from unscheduled_models import registry

ORIGIN = "scripts/build_registry.py"


def comparable(export: dict[str, Any]) -> list[tuple[Any, ...]]:
    """What a rebuild must reproduce: per version, its model, number, role, stage and numbers."""
    rows: list[tuple[Any, ...]] = []
    for model in export["models"]:
        for v in model["versions"]:
            rows.append(
                (
                    model["name"],
                    v["version"],
                    v["role"],
                    v["stage"],
                    v["chosen"],
                    json.dumps(v["params"], sort_keys=True),
                    json.dumps({k: round(x, 9) for k, x in v["dev"].items()}, sort_keys=True),
                    json.dumps({k: round(x, 9) for k, x in v["test"].items()}, sort_keys=True),
                )
            )
    return rows


def planned(root: Path) -> list[tuple[Any, ...]]:
    versions, _missing = registry.plan(root)
    return [
        (
            v.candidate.model,
            v.version,
            v.candidate.role,
            v.stage,
            v.chosen,
            json.dumps(v.params, sort_keys=True),
            json.dumps({k: round(x, 9) for k, x in v.dev.items()}, sort_keys=True),
            json.dumps({k: round(x, 9) for k, x in v.test.items()}, sort_keys=True),
        )
        for v in versions
    ]


def manifest_part(export: dict[str, Any], as_of: str) -> dict[str, Any]:
    m = ManifestBuilder(as_of)
    versions = [v for model in export["models"] for v in model["versions"]]
    m.value(
        "models.registry.models",
        len(export["models"]),
        "int",
        origin=ORIGIN,
        population="registered models in the MLflow store",
        source="models",
    )
    m.value(
        "models.registry.versions",
        len(versions),
        "int",
        origin=ORIGIN,
        population="model versions in the MLflow store, one per candidate",
        source="models",
    )
    m.value(
        "models.registry.archive",
        export["archive"]["file"],
        "text",
        origin=ORIGIN,
        population="the packed store, named by the first twelve characters of its SHA-256",
        source="models",
    )
    m.value(
        "models.registry.mlflow",
        export["tracking"]["mlflow"],
        "text",
        origin=ORIGIN,
        population="the MLflow version that wrote the store",
        source="models",
    )
    m.table(
        "models.registry.versions_table",
        ["Registered model", "Version", "Role", "Stage", "Run"],
        ["text", "int", "text", "text", "text"],
        [
            [model["name"], v["version"], v["role"], v["stage"], v["run_name"]]
            for model in export["models"]
            for v in model["versions"]
        ],
        origin=ORIGIN,
        population="every version in the registry",
        source="models",
    )
    return m.dump()


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--store", type=Path, default=root / "data" / "registry" / "store")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    target = root / "results" / "registry" / "registry.json"
    if args.check:
        committed = json.loads(target.read_text(encoding="utf-8"))
        if comparable(committed) != planned(root):
            print("registry: the committed export differs from what the records give; rebuild it")
            return 1
        print(f"registry: {len(planned(root))} versions match the committed export")
        return 0
    export = registry.build(root, args.store)
    rewritten = registry.relocate(args.store)
    archive, digest = registry.pack(args.store, root / "results" / "registry")
    export["archive"] = {
        "file": archive.name,
        "sha256": digest,
        "bytes": archive.stat().st_size,
        "paths_made_relative": rewritten,
        "open": "tar xzf the archive, then mlflow ui --backend-store-uri sqlite:///mlflow.db in store/",
    }
    target.write_text(json.dumps(export, indent=1) + "\n", encoding="utf-8")
    sets_record = json.loads((root / "results" / "models" / "sets.json").read_text(encoding="utf-8"))
    part = manifest_part(export, str(sets_record["lake_cut"])[:10])
    (root / "results" / "parts" / "registry.json").write_text(
        json.dumps(part, indent=1) + "\n", encoding="utf-8"
    )
    versions = sum(len(m["versions"]) for m in export["models"])
    print(
        f"registry: {len(export['models'])} models, {versions} versions, {archive.name} "
        f"({archive.stat().st_size} bytes); records not committed yet: {export['records_missing'] or 'none'}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
