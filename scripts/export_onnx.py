"""Export the models /v1/predict runs to ONNX, with the specs the API builds their inputs from, and
measure their parity with the native models.

    uv run python scripts/export_onnx.py [--models data/models] [--sets data/sets] [--rows 2000]

Reads the band floor from data/models/floors/floors.joblib and LightGBM with its day 0 design from
data/models/rank/rank.joblib (the artifacts of the floors and exploitation runs, checked against the
SHA-256 their committed records name). Writes models/serving/band_floor.onnx with its input spec
band_floor.json.gz, and models/serving/exploit_lgbm.onnx with exploit_day0.json, then draws --rows
development CVEs with the default seed and compares, on rows built the API's way: every feature and
probability of the floor, and every input and probability of LightGBM, with its band projection
taken from the ONNX floor as the API takes it. Commits results/models/onnx.json and the manifest part
results/parts/onnx.json; fails if a probability differs by more than 1e-4.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import joblib
import lightgbm as lgb
import numpy as np
import onnx
import polars as pl
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_models import embed, export, rank, sets

from scripts.train_floors import file_sha256, plan_seed, verify_sets

ORIGIN = "scripts/export_onnx.py"
SERVING = Path("models") / "serving"


def checked(root: Path, record_name: str, path: Path) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(
        (root / "results" / "models" / f"{record_name}.json").read_text(encoding="utf-8")
    )
    if record.get("sample"):
        raise SystemExit(f"export: results/models/{record_name}.json is a sample run")
    if file_sha256(path) != record["model_file"]["sha256"]:
        raise SystemExit(f"export: {path} is not the model file results/models/{record_name}.json names")
    return record


def write_model(model: onnx.ModelProto, path: Path) -> dict[str, Any]:
    data = model.SerializeToString()
    path.write_bytes(data)
    return {"file": path.as_posix(), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def write_spec(spec: dict[str, Any], path: Path) -> dict[str, Any]:
    text = json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()
    data = gzip.compress(text, compresslevel=9, mtime=0) if path.suffix == ".gz" else text
    path.write_bytes(data)
    return {"file": path.as_posix(), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def manifest_part(record: dict[str, Any], as_of: str) -> dict[str, Any]:
    m = ManifestBuilder(as_of)
    for name in ("band_floor", "exploit_lgbm"):
        m.value(
            f"models.onnx.{name}.max_probability_difference",
            float(record["parity"][name]["max_probability_difference"]),
            "sci1",
            origin=ORIGIN,
            population=f"{record['parity'][name]['rows']} development CVEs drawn with the default seed",
            source="models",
        )
        m.value(
            f"models.onnx.{name}.megabytes",
            round(record["files"][name]["bytes"] / 1e6, 1),
            "float1",
            origin=ORIGIN,
            population=f"the ONNX file of {name}",
            source="models",
        )
    for key, name in (
        ("projection_against_the_exploitation_run", "projection_gap"),
        ("lgbm_score_against_the_exploitation_run", "score_gap"),
    ):
        if record["parity"].get(key) is not None:
            m.value(
                f"models.onnx.{name}",
                float(record["parity"][key]),
                "float4",
                origin=ORIGIN,
                population=(
                    f"{record['parity']['band_floor']['rows']} development CVEs: the committed band floor "
                    "against the refit the exploitation run used, largest absolute difference"
                ),
                source="models",
            )
    m.value(
        "models.onnx.parity",
        record["verdict"],
        "text",
        origin=ORIGIN,
        population="every probability within the tolerance of evaluation: 1e-4",
        source="models",
    )
    return m.dump()


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--models", type=Path, default=root / "data" / "models")
    parser.add_argument("--sets", type=Path, default=root / "data" / "sets")
    parser.add_argument("--rows", type=int, default=2000)
    args = parser.parse_args(argv)
    seed = plan_seed(root)
    floors_file = args.models / "floors" / "floors.joblib"
    rank_file = args.models / "rank" / "rank.joblib"
    floors_record = checked(root, "floors", floors_file)
    checked(root, "rank", rank_file)
    verify_sets(root, args.sets, names=("development_inputs.parquet",))
    saved = joblib.load(floors_file)
    features, band = saved["features"], saved["models"]["band"]
    ranked = joblib.load(rank_file)
    design, booster = ranked["design"], lgb.Booster(model_str=ranked["lgbm"])
    out = root / SERVING
    out.mkdir(parents=True, exist_ok=True)
    spec = export.floor_spec(features)
    # scikit-learn keeps the classes sorted by name; the API and LightGBM's projection read the
    # columns in BANDS order, so the graph is written with its estimators in that order.
    fitted = [str(c) for c in band.classes_]
    if sorted(fitted) != sorted(sets.BANDS):
        raise SystemExit(f"export: the band floor's classes are {fitted}, not {list(sets.BANDS)}")
    classes = list(sets.BANDS)
    estimators = [band.estimators_[fitted.index(b)] for b in classes]
    floor_graph = export.linear_onnx(estimators, classes, spec["width"], "band_floor")
    day0 = export.day0_spec(design)
    width = len(design.names())
    lgbm_graph = export.lgbm_onnx(booster, width)
    files = {
        "band_floor": write_model(floor_graph, out / "band_floor.onnx"),
        "band_floor_spec": write_spec(spec, out / "band_floor.json.gz"),
        "exploit_lgbm": write_model(lgbm_graph, out / "exploit_lgbm.onnx"),
        "exploit_day0": write_spec(day0, out / "exploit_day0.json"),
    }
    for entry in files.values():
        entry["file"] = Path(entry["file"]).relative_to(root).as_posix()
    dev = pl.read_parquet(args.sets / "development_inputs.parquet")
    sample = dev.sample(n=min(args.rows, dev.height), seed=seed, shuffle=False).sort("cve_id")
    floor_result = export.floor_parity(band, features, sample, spec, floor_graph)
    # LightGBM's projection comes from the ONNX floor, as the API computes it.
    projection = export.floor_onnx_proba(floor_graph, spec, sample)
    with_projection = rank.with_projection(sample, projection.astype(np.float64))
    lgbm_result = export.lgbm_parity(booster, design, with_projection, day0, lgbm_graph)
    # The exploitation run refit the band floor for its projection; the API uses the committed
    # floor. Both gaps are kept: in the projection, and in LightGBM's score on these rows.
    scores_file = args.models / "rank" / "development_scores.parquet"
    projection_gap = score_gap = None
    if scores_file.exists():
        trained = sample.select("cve_id").join(pl.read_parquet(scores_file), on="cve_id", how="left")
        projection_gap = float(
            np.max(np.abs(trained.select(list(rank.PROJECTION)).to_numpy() - projection.astype(np.float64)))
        )
        served = np.asarray(booster.predict(design.dense(with_projection)), dtype=np.float64)
        score_gap = float(np.max(np.abs(trained.get_column("exploit_lgbm").to_numpy() - served)))
    worst = max(floor_result["max_probability_difference"], lgbm_result["max_probability_difference"])
    record = {
        "tolerance": export.TOLERANCE,
        "opset": export.OPSET,
        "seed": seed,
        "band_floor": {
            "variant": spec["variant"],
            "width": spec["width"],
            "classes": classes,
            "C": floors_record["chosen"]["band"]["C"],
        },
        "exploit_lgbm": {"width": width, "trees": booster.num_trees()},
        "files": files,
        "parity": {
            "band_floor": floor_result,
            "exploit_lgbm": lgbm_result,
            "projection_against_the_exploitation_run": projection_gap,
            "lgbm_score_against_the_exploitation_run": score_gap,
        },
        "verdict": "pass" if worst <= export.TOLERANCE else "fail",
        "environment": {"onnx": onnx.__version__, "onnxruntime": embed.runtime_version()},
    }
    (root / "results" / "models" / "onnx.json").write_text(
        json.dumps(record, indent=1) + "\n", encoding="utf-8"
    )
    sets_record = json.loads((root / "results" / "models" / "sets.json").read_text(encoding="utf-8"))
    part = manifest_part(record, str(sets_record["lake_cut"])[:10])
    (root / "results" / "parts" / "onnx.json").write_text(json.dumps(part, indent=1) + "\n", encoding="utf-8")
    print(
        f"export: floor {floor_result['max_probability_difference']:.2e}, LightGBM "
        f"{lgbm_result['max_probability_difference']:.2e}, projection gap {projection_gap}, score gap "
        f"{score_gap}: {record['verdict']}"
    )
    return 0 if record["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
