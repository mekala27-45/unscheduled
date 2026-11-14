"""The batch predictions: one row per CVE of the windows no model was fit on, from the chosen versions,
calibrated and with their sets, the same bytes on a second run."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import polars as pl
import yaml

from scripts import predict_serving

METRICS = {
    "AV": ["N", "L", "A", "P"],
    "AC": ["L", "H"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "R"],
    "S": ["U", "C"],
    "C": ["H", "L", "N"],
    "I": ["H", "L", "N"],
    "A": ["H", "L", "N"],
}
CWES = ["CWE-79", "CWE-89", "CWE-787", "CWE-20", "CWE-22", "other"]


def probabilities(rng: np.random.Generator, n: int, k: int) -> np.ndarray:
    return rng.dirichlet(np.ones(k), n).astype(np.float32)


def write_root(root: Path) -> None:
    rng = np.random.default_rng(1)
    for folder in (
        "data/sets",
        "data/models/fallback",
        "data/models/rank",
        "data/models/survival",
        "data/models/product",
        "config",
        "results/registry",
        "results/models",
        "results/parts",
    ):
        (root / folder).mkdir(parents=True, exist_ok=True)
    for split, n in (("development", 30), ("test", 20), ("shadow", 25)):
        ids = [f"CVE-2025-{split[:2]}{i:04d}" for i in range(n)]
        filer_bands = [["LOW", "HIGH", None, "NONE"][i % 4] for i in range(n)]
        pl.DataFrame(
            {"cve_id": ids, "filer_band": filer_bands}, schema_overrides={"filer_band": pl.String}
        ).write_parquet(root / f"data/sets/{split}_inputs.parquet")
        columns: dict[str, object] = {"cve_id": ids}
        for j, band in enumerate(probabilities(rng, n, 4).T):
            columns[f"band__{['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][j]}"] = band
        for m, values in METRICS.items():
            for j, col in enumerate(probabilities(rng, n, len(values)).T):
                columns[f"metric_{m}__{values[j]}"] = col
        for j, col in enumerate(probabilities(rng, n, len(CWES)).T):
            columns[f"cwe__{CWES[j]}"] = col
        pl.DataFrame(columns).write_parquet(root / f"data/models/fallback/{split}_probabilities.parquet")
        pl.DataFrame(
            {"cve_id": ids, "exploit_lgbm": rng.random(n), "exploit_floor": rng.random(n)}
        ).write_parquet(root / f"data/models/rank/{split}_scores.parquet")
        surv = {"cve_id": ids}
        for model in ("cox", "forest"):
            for h in (30, 90, 180):
                surv[f"{model}_listed_by_{h}"] = (rng.random(n) * h / 400).astype(np.float32)  # type: ignore[assignment]
        pl.DataFrame(surv).write_parquet(root / f"data/models/survival/{split}_survival.parquet")
        keys = [[f"acme:door{k}" for k in range(i % 7)] for i in range(n)]
        pl.DataFrame(
            {"cve_id": ids, "floor_keys": keys, "retrieval_keys": [list(reversed(k)) for k in keys]},
            schema={
                "cve_id": pl.String,
                "floor_keys": pl.List(pl.String),
                "retrieval_keys": pl.List(pl.String),
            },
        ).write_parquet(root / f"data/models/product/{split}_candidates.parquet")
    heads = {"band": 1.2, "cwe": 0.9, **{f"metric_{m}": 1.0 for m in METRICS}}
    points = {
        "primary": {"fill": "fallback", "fill_design": "joint", "exploitation": "exploit_lgbm"},
        "temperatures": {"fallback": heads, "floors": heads},
        "conformal": {
            "target": 0.9,
            "cutoffs": {h: 0.8 for h in heads if h != "cwe"},
            "floor_band_cutoff": 0.85,
        },
    }
    (root / "config/operating_points.yaml").write_text(yaml.safe_dump(points), encoding="utf-8")
    models = [
        {
            "name": name,
            "aliases": {"chosen": chosen},
            "versions": [
                {"version": v, "run_name": f"{name} {v}", "role": "floor" if v == 1 else "model"}
                for v in range(1, 4)
            ],
        }
        for name, chosen in (
            ("unscheduled-band", 3),
            ("unscheduled-metrics", 3),
            ("unscheduled-cwe", 3),
            ("unscheduled-exploit", 2),
            ("unscheduled-survival", 1),
            ("unscheduled-product", 2),
        )
    ]
    (root / "results/registry/registry.json").write_text(json.dumps({"models": models}), encoding="utf-8")
    calibration = {"exploitation": {"exploit_lgbm": {"map": {"x": [0.0, 0.5, 1.0], "y": [0.0, 0.1, 0.4]}}}}
    (root / "results/models/calibration.json").write_text(json.dumps(calibration), encoding="utf-8")
    (root / "results/models/sets.json").write_text(
        json.dumps({"lake_cut": "2026-11-13T06:00:00+00:00"}), encoding="utf-8"
    )


def test_every_window_row_gets_a_prediction_from_the_chosen_versions(tmp_path: Path) -> None:
    write_root(tmp_path)
    assert (
        predict_serving.main(
            ["--models", str(tmp_path / "data/models"), "--sets", str(tmp_path / "data/sets")], root=tmp_path
        )
        == 0
    )
    table = pl.read_parquet(tmp_path / predict_serving.TARGET)
    assert table.height == 75 and table.get_column("cve_id").is_unique().all()
    assert set(table.get_column("window")) == {"development", "test", "shadow"}
    probs = table.select([c for c in table.columns if c.startswith("band_p_")]).to_numpy()
    assert np.allclose(probs.sum(axis=1), 1.0, atol=1e-5)
    # The band is the most probable, and its set holds it.
    assert all(
        b in s.split("|") for b, s in zip(table.get_column("band"), table.get_column("band_set"), strict=True)
    )
    assert table.get_column("exploit_pct").min() > 0 and table.get_column("exploit_pct").max() == 100
    assert table.get_column("exploit_p").is_between(0, 0.4).all()
    # Survival takes the chosen Cox model, the product the chosen retrieval.
    shadow = pl.read_parquet(tmp_path / "data/models/survival/shadow_survival.parquet")
    row = table.filter(pl.col("cve_id") == shadow.get_column("cve_id")[3])
    assert row.get_column("listed_by_90").item() == shadow.get_column("cox_listed_by_90")[3]
    assert all(len(p.split("|")) <= 5 for p in table.get_column("products") if p)
    record = json.loads((tmp_path / "results/models/predictions.json").read_text(encoding="utf-8"))
    assert record["survival_model"] == "cox" and record["product_model"] == "retrieval"
    # The shadow view counts every shadow CVE once, by predicted band and filer band.
    counts = record["shadow_bands"]
    assert [r[0] for r in counts] == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert sum(r[-1] for r in counts) == 25 and all(sum(r[1:-1]) == r[-1] for r in counts)
    # Columns: the band, filer LOW, MEDIUM, HIGH, CRITICAL, NONE, no filer band, and all.
    assert [sum(r[j] for r in counts) for j in range(1, 7)] == [7, 0, 6, 0, 6, 6]
    part = json.loads((tmp_path / "results/parts/predictions.json").read_text(encoding="utf-8"))
    assert "models.predictions.shadow_bands" in part["tables"]
    serving = json.loads((tmp_path / "models/serving/serving.json").read_text(encoding="utf-8"))
    assert serving["band_floor"]["version"] == 1 and serving["exploit"]["version"] == 2
    assert len(serving["exploit"]["quantiles"]) == 1001
    first = (tmp_path / predict_serving.TARGET).read_bytes()
    predict_serving.main(
        ["--models", str(tmp_path / "data/models"), "--sets", str(tmp_path / "data/sets")], root=tmp_path
    )
    assert (tmp_path / predict_serving.TARGET).read_bytes() == first
