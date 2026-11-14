"""Draw the band misses the failure taxonomy is read from, and check the codes given to them.

    uv run python scripts/draw_misses.py draw    # results/models/misses.json, the 100 to read
    uv run python scripts/draw_misses.py check   # the codes in results/models/taxonomy.json

The plan reads "100 band misses drawn with the default seed from development, coded by reading into
categories named while reading, with counts in the manifest. Never from test"
(evaluation/phase2_plan.yaml, failure_taxonomy). A miss is a development CVE with an NVD band whose
band from the primary fill model (the most probable of its four, config/operating_points.yaml)
differs from it. draw writes each one with what a reader needs: the day 0 description, the filer
and its vector, the filer band, the CISA values, the predicted band with its probabilities, and
the NVD band and base metrics. The codes are written by hand into results/models/taxonomy.json, one
category per miss; check confirms every drawn miss has exactly one code from a named category,
counts them, and writes the manifest part results/parts/taxonomy.json.
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

import numpy as np
import polars as pl
import yaml
from unscheduled_core.manifest import ManifestBuilder
from unscheduled_models import calibrate, sets

from scripts.train_floors import plan_seed

ORIGIN = "scripts/draw_misses.py"
DRAWN = 100
METRICS = sets.METRICS


def primary_temperature(root: Path) -> tuple[str, float, str]:
    """The primary fill model and its band temperature: from the frozen operating points, or before
    they are frozen from the calibration fit on development they will freeze. A temperature never
    changes which band is most probable, so the misses are the same either way; it only scales the
    probabilities a reader sees."""
    points_path = root / "config" / "operating_points.yaml"
    if points_path.exists():
        points = yaml.safe_load(points_path.read_text(encoding="utf-8"))
        primary = points["primary"]["fill"]
        return primary, float(points["temperatures"][primary]["band"]), "config/operating_points.yaml"
    calibration = json.loads((root / "results" / "models" / "calibration.json").read_text(encoding="utf-8"))
    primary = calibration["primary_fill"]
    return (
        primary,
        float(calibration["fill"][primary]["band"]["temperature"]),
        "results/models/calibration.json",
    )


def draw(root: Path, models: Path, folder: Path) -> dict[str, Any]:
    primary, temperature, temperature_from = primary_temperature(root)
    proba = pl.read_parquet(models / primary / "development_probabilities.parquet")
    labels = pl.read_parquet(folder / "development_labels.parquet")
    inputs = pl.read_parquet(folder / "development_inputs.parquet")
    frame = (
        labels.filter(pl.col("band").is_in(list(sets.BANDS)))
        .join(inputs, on=["cve_id", "split"], how="inner")
        .join(proba, on="cve_id", how="inner")
        .sort("cve_id")
    )
    columns = [f"band__{b}" for b in sets.BANDS]
    scaled = calibrate.scale(frame.select(columns).to_numpy().astype(np.float64), temperature)
    predicted = [sets.BANDS[i] for i in scaled.argmax(axis=1)]
    frame = frame.with_columns(pl.Series("predicted_band", predicted))
    misses = frame.with_row_index("position").filter(pl.col("predicted_band") != pl.col("band"))
    seed = plan_seed(root)
    picked = misses.sample(n=min(DRAWN, misses.height), seed=seed, shuffle=False).sort("cve_id")
    rows = []
    for r in picked.to_dicts():
        i = int(r["position"])
        rows.append(
            {
                "cve_id": r["cve_id"],
                "published": str(r["published"])[:10],
                "description": r["description"],
                "filer": r["filer"],
                "filer_type": r["filer_type"],
                "filer_vector": r["filer_cvss31_vector"]
                or r["filer_cvss30_vector"]
                or r["filer_cvss40_vector"],
                "filer_band": r["filer_band"],
                "filer_cwes": r["filer_cwes"],
                "products": r["products"],
                "adp_band": r["adp_band"],
                "adp_ssvc_exploitation": r["adp_ssvc_exploitation"],
                "predicted_band": r["predicted_band"],
                "probabilities": {b: round(float(scaled[i, j]), 4) for j, b in enumerate(sets.BANDS)},
                "nvd_band": r["band"],
                "nvd_metrics": "/".join(f"{m}:{r[f'nvd_{m}']}" for m in METRICS),
                "nvd_cwe": r["cwe"],
            }
        )
    record = {
        "plan": "evaluation/phase2_plan.yaml, failure_taxonomy",
        "model": primary,
        "temperature": temperature,
        "temperature_from": temperature_from,
        "seed": seed,
        "development_rows_with_band": frame.height,
        "development_misses": misses.height,
        "drawn": len(rows),
        "rule": "a development CVE with an NVD band whose predicted band, the most probable after the frozen temperature, differs",
        "misses": rows,
    }
    (root / "results" / "models" / "misses.json").write_text(
        json.dumps(record, indent=1) + "\n", encoding="utf-8"
    )
    return record


def check(root: Path) -> dict[str, Any]:
    misses = json.loads((root / "results" / "models" / "misses.json").read_text(encoding="utf-8"))
    taxonomy: dict[str, Any] = json.loads(
        (root / "results" / "models" / "taxonomy.json").read_text(encoding="utf-8")
    )
    named = {c["name"] for c in taxonomy["categories"]}
    codes: dict[str, str] = taxonomy["codes"]
    drawn = [m["cve_id"] for m in misses["misses"]]
    missing = [c for c in drawn if c not in codes]
    extra = [c for c in codes if c not in set(drawn)]
    unnamed = sorted({v for v in codes.values() if v not in named})
    if missing or extra or unnamed:
        raise SystemExit(f"taxonomy: missing {missing[:5]}, extra {extra[:5]}, unnamed {unnamed}")
    counts = {name: sum(1 for v in codes.values() if v == name) for name in named}
    for category in taxonomy["categories"]:
        category["count"] = counts[category["name"]]
    taxonomy["categories"].sort(key=lambda c: (-c["count"], c["name"]))
    taxonomy["drawn"] = len(drawn)
    (root / "results" / "models" / "taxonomy.json").write_text(
        json.dumps(taxonomy, indent=1) + "\n", encoding="utf-8"
    )
    sets_record = json.loads((root / "results" / "models" / "sets.json").read_text(encoding="utf-8"))
    m = ManifestBuilder(str(sets_record["lake_cut"])[:10])
    m.table(
        "models.taxonomy",
        ["Category", "Misses", "What it means"],
        ["text", "int", "text"],
        [[c["name"], c["count"], c["meaning"]] for c in taxonomy["categories"]],
        origin=ORIGIN,
        population=f"{len(drawn)} development band misses of the primary fill model, drawn with the default seed",
        source="models",
    )
    m.value(
        "models.taxonomy.drawn",
        len(drawn),
        "int",
        origin=ORIGIN,
        population="development band misses drawn with the default seed and read by hand",
        source="models",
    )
    m.value(
        "models.taxonomy.misses",
        int(misses["development_misses"]),
        "int",
        origin=ORIGIN,
        population="development CVEs with an NVD band the primary fill model gets wrong",
        source="models",
    )
    (root / "results" / "parts" / "taxonomy.json").write_text(
        json.dumps(m.dump(), indent=1) + "\n", encoding="utf-8"
    )
    return taxonomy


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("draw", "check"))
    parser.add_argument("--models", type=Path, default=root / "data" / "models")
    parser.add_argument("--sets", type=Path, default=root / "data" / "sets")
    args = parser.parse_args(argv)
    if args.action == "draw":
        record = draw(root, args.models, args.sets)
        print(f"misses: drew {record['drawn']} of {record['development_misses']} development misses")
    else:
        taxonomy = check(root)
        print("taxonomy: " + ", ".join(f"{c['name']} {c['count']}" for c in taxonomy["categories"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
