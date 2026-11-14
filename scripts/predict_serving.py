"""Write the batch predictions the API serves, from the frozen operating points and the chosen models.

    uv run python scripts/predict_serving.py [--models data/models] [--sets data/sets]

Every CVE of the development, test and shadow windows gets one row (evaluation/phase2_plan.yaml,
predictions): the windows no model was fit on, published from 2024 on, all inside the serving slice.
A train window CVE gets none, since the models were fit on it and its prediction would be surer than
any new CVE's, and the gap window gets none, since no model uses it. Each row holds, from the chosen
version of each registered model (results/registry/registry.json): the band with its four
probabilities scaled by the frozen temperature and its 90 percent conformal set; each base metric
the same way; the CWE with its probability and its five most probable classes; the raw exploitation
score, its isotonic probability and its percentile among every CVE of the batch; the chance of a KEV
listing by 30, 90 and 180 days; and the five most likely affected products. Writes
models/serving/predictions.parquet (committed, read by the serving bundle), results/models/
predictions.json and the manifest part results/parts/predictions.json. Reads no test label.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import numpy as np
import polars as pl
import yaml
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_models import calibrate, conformal, sets

ORIGIN = "scripts/predict_serving.py"
SPLITS = ("development", "test", "shadow")
TARGET = Path("models") / "serving" / "predictions.parquet"
TOP_CWE = 5
TOP_PRODUCTS = 5
SURVIVAL_COLUMNS = {"unscheduled-survival": {1: "cox", 2: "forest"}}
PRODUCT_COLUMNS = {1: "floor", 2: "retrieval"}


def head(proba: pl.DataFrame, task: str) -> tuple[np.ndarray, list[str]]:
    columns = [c for c in proba.columns if c.startswith(f"{task}__")]
    return proba.select(columns).to_numpy().astype(np.float64), [c.split("__", 1)[1] for c in columns]


def joined(values: list[str], member: np.ndarray, order: list[str]) -> str:
    """A set as its members in the order given, joined by a bar."""
    kept = {v for v, m in zip(values, member, strict=True) if m}
    return "|".join(v for v in order if v in kept)


def chosen_versions(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for model in registry["models"]:
        version = model["aliases"].get("chosen")
        if version is None:
            raise SystemExit(f"predict: {model['name']} has no chosen version in the registry")
        entry = next(v for v in model["versions"] if v["version"] == version)
        out[model["name"]] = {"version": version, "run_name": entry["run_name"], "role": entry["role"]}
    return out


def fill_columns(proba: pl.DataFrame, points: dict[str, Any]) -> dict[str, Any]:
    temperatures = points["temperatures"][points["primary"]["fill"]]
    cutoffs = points["conformal"]["cutoffs"]
    out: dict[str, Any] = {}
    p, classes = head(proba, "band")
    scaled = calibrate.scale(p, float(temperatures["band"]))
    order = [b for b in sets.BANDS if b in classes]
    best = scaled.argmax(axis=1)
    out["band"] = [classes[j] for j in best]
    for b in sets.BANDS:
        out[f"band_p_{b.lower()}"] = scaled[:, classes.index(b)].astype(np.float32)
    member = conformal.sets(scaled, float(cutoffs["band"]))
    out["band_set"] = [joined(classes, row, order) for row in member]
    for m in sets.METRICS:
        task = f"metric_{m}"
        p, classes = head(proba, task)
        scaled = calibrate.scale(p, float(temperatures[task]))
        best = scaled.argmax(axis=1)
        out[task] = [classes[j] for j in best]
        out[f"{task}_p"] = scaled[np.arange(len(best)), best].astype(np.float32)
        member = conformal.sets(scaled, float(cutoffs[task]))
        ranked = [classes[j] for j in np.argsort(-scaled.mean(axis=0))]
        out[f"{task}_set"] = [joined(classes, row, ranked) for row in member]
    p, classes = head(proba, "cwe")
    scaled = calibrate.scale(p, float(temperatures["cwe"]))
    top = np.argsort(-scaled, axis=1, kind="stable")[:, :TOP_CWE]
    out["cwe"] = [classes[row[0]] for row in top]
    out["cwe_p"] = scaled[np.arange(len(top)), top[:, 0]].astype(np.float32)
    out["cwe_top"] = ["|".join(classes[j] for j in row) for row in top]
    return out


def percentile(values: np.ndarray) -> np.ndarray:
    """Each value's percentile among all of them: the share at or below it, times 100."""
    order = np.sort(values)
    return (np.searchsorted(order, values, side="right") / len(values) * 100.0).astype(np.float32)


def manifest_part(record: dict[str, Any], as_of: str) -> dict[str, Any]:
    m = ManifestBuilder(as_of)
    m.value(
        "models.predictions.rows",
        int(record["rows"]),
        "int",
        origin=ORIGIN,
        population="development, test and shadow window CVEs, one row each",
        source="models",
    )
    m.value(
        "models.predictions.megabytes",
        round(record["file"]["bytes"] / 1e6, 1),
        "float1",
        origin=ORIGIN,
        population="models/serving/predictions.parquet",
        source="models",
    )
    m.value(
        "models.predictions.batch",
        record["batch"],
        "text",
        origin=ORIGIN,
        population="the first twelve characters of the SHA-256 over the operating points and the chosen versions",
        source="models",
    )
    for split in SPLITS:
        m.value(
            f"models.predictions.{split}.rows",
            int(record["windows"][split]),
            "int",
            origin=ORIGIN,
            population=f"{split} window CVEs with a prediction",
            source="models",
        )
    return m.dump()


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--models", type=Path, default=root / "data" / "models")
    parser.add_argument("--sets", type=Path, default=root / "data" / "sets")
    args = parser.parse_args(argv)
    points_path = root / "config" / "operating_points.yaml"
    if not points_path.exists():
        raise SystemExit("predict: config/operating_points.yaml is not written yet (step nine)")
    points = yaml.safe_load(points_path.read_text(encoding="utf-8"))
    registry = json.loads((root / "results" / "registry" / "registry.json").read_text(encoding="utf-8"))
    calibration = json.loads((root / "results" / "models" / "calibration.json").read_text(encoding="utf-8"))
    versions = chosen_versions(registry)
    survival_model = SURVIVAL_COLUMNS["unscheduled-survival"][versions["unscheduled-survival"]["version"]]
    product_model = PRODUCT_COLUMNS[versions["unscheduled-product"]["version"]]
    iso = calibration["exploitation"][points["primary"]["exploitation"]]["map"]
    isotonic = calibrate.Isotonic(np.asarray(iso["x"]), np.asarray(iso["y"]))
    frames: list[pl.DataFrame] = []
    windows: dict[str, int] = {}
    for split in SPLITS:
        ids = pl.read_parquet(args.sets / f"{split}_inputs.parquet", columns=["cve_id"])
        fill = ids.join(
            pl.read_parquet(args.models / points["primary"]["fill"] / f"{split}_probabilities.parquet"),
            on="cve_id",
            how="left",
        )
        if fill.null_count().sum_horizontal().item():
            raise SystemExit(f"predict: the fill probabilities miss {split} rows")
        columns: dict[str, Any] = {"cve_id": fill.get_column("cve_id"), "window": [split] * fill.height}
        columns.update(fill_columns(fill, points))
        scores = ids.join(
            pl.read_parquet(args.models / "rank" / f"{split}_scores.parquet"), on="cve_id", how="left"
        )
        raw = scores.get_column(points["primary"]["exploitation"]).cast(pl.Float64).to_numpy()
        columns["exploit_score"] = raw.astype(np.float32)
        columns["exploit_p"] = isotonic.predict(raw).astype(np.float32)
        surv = ids.join(
            pl.read_parquet(args.models / "survival" / f"{split}_survival.parquet"), on="cve_id", how="left"
        )
        for h in (30, 90, 180):
            columns[f"listed_by_{h}"] = surv.get_column(f"{survival_model}_listed_by_{h}").cast(pl.Float32)
        cands = ids.join(
            pl.read_parquet(args.models / "product" / f"{split}_candidates.parquet"), on="cve_id", how="left"
        )
        columns["products"] = [
            "|".join((keys or [])[:TOP_PRODUCTS])
            for keys in cands.get_column(f"{product_model}_keys").to_list()
        ]
        frames.append(pl.DataFrame(columns))
        windows[split] = fill.height
    table = pl.concat(frames).sort("cve_id")
    table = table.with_columns(
        pl.Series("exploit_pct", percentile(table.get_column("exploit_score").to_numpy()))
    )
    digest = hashlib.sha256(
        points_path.read_bytes() + json.dumps(versions, sort_keys=True).encode()
    ).hexdigest()
    batch = digest[:12]
    table = table.with_columns(pl.lit(batch).alias("batch"))
    target = root / TARGET
    target.parent.mkdir(parents=True, exist_ok=True)
    table.write_parquet(target, compression="zstd", compression_level=19, statistics=False)
    record = {
        "batch": batch,
        "rows": table.height,
        "windows": windows,
        "columns": table.columns,
        "versions": versions,
        "survival_model": survival_model,
        "product_model": product_model,
        "rule": "development, test and shadow window CVEs; train window CVEs carry none since the models were fit on them",
        "file": {
            "path": TARGET.as_posix(),
            "bytes": target.stat().st_size,
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "content_digest": sets.content_digest(target),
        },
    }
    (root / "results" / "models" / "predictions.json").write_text(
        json.dumps(record, indent=1) + "\n", encoding="utf-8"
    )
    sets_record = json.loads((root / "results" / "models" / "sets.json").read_text(encoding="utf-8"))
    part = manifest_part(record, str(sets_record["lake_cut"])[:10])
    (root / "results" / "parts" / "predictions.json").write_text(
        json.dumps(part, indent=1) + "\n", encoding="utf-8"
    )
    print(f"predict: {table.height} rows, batch {batch}, {target.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
