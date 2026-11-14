"""The single test scoring, run end to end on invented files of the real shapes, so the one real run
cannot be the first time its code meets them."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import polars as pl
import yaml
from unscheduled_models import sets

from scripts import score_test

ROOT = Path(__file__).resolve().parents[2]
BANDS = list(sets.BANDS)
METRICS = {
    "AV": ["N", "L"],
    "AC": ["L", "H"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "R"],
    "S": ["U", "C"],
    "C": ["H", "L", "N"],
    "I": ["H", "L", "N"],
    "A": ["H", "L", "N"],
}
CWES = ["CWE-79", "CWE-89", "CWE-20", "other"]
FILERS = ["acme", "globex", "initech", "umbrella"]


def probabilities(rng: np.random.Generator, truth: list[str], classes: list[str], skill: float) -> np.ndarray:
    """Rows that lean toward the true class by skill, so a model and a floor differ."""
    out = rng.dirichlet(np.ones(len(classes)), len(truth))
    for i, t in enumerate(truth):
        if t in classes:
            out[i, classes.index(t)] += skill
    return out / out.sum(axis=1, keepdims=True)


def write_root(root: Path, n: int = 900) -> None:
    rng = np.random.default_rng(11)
    for folder in (
        "evaluation",
        "config",
        "results/models",
        "results/parts",
        "data/sets",
        "data/bronze/epss_offsets",
        "data/models/floors",
        "data/models/fallback",
        "data/models/rank",
        "data/models/survival",
        "data/models/product",
    ):
        (root / folder).mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "config" / "criteria.yaml", root / "config" / "criteria.yaml")
    (root / "evaluation" / "plan_seed.txt").write_text("", encoding="utf-8")
    ids = [f"CVE-2025-{i:05d}" for i in range(n)]
    start = datetime(2025, 1, 1, tzinfo=UTC)
    published = [start + timedelta(days=int(d)) for d in rng.integers(0, 450, n)]
    band = [BANDS[i % 4] if i % 7 else None for i in range(n)]
    kev = rng.random(n) < 0.04
    labels: dict[str, object] = {
        "cve_id": ids,
        "split": ["test"] * n,
        "band": band,
        "cwe": [CWES[i % 4] for i in range(n)],
        "kev_180": kev,
        "kev_q03": [False] * n,
        "days_to_kev": [int(d) if k else 300 for d, k in zip(rng.integers(0, 180, n), kev, strict=True)],
        "kev_event": kev,
    }
    for m, values in METRICS.items():
        labels[f"nvd_{m}"] = [values[i % len(values)] if band[i] else None for i in range(n)]
    pl.DataFrame(labels).write_parquet(root / "data/sets" / sets.TEST_LABELS)
    filer = [FILERS[i % 4] for i in range(n)]
    pl.DataFrame(
        {
            "cve_id": ids,
            "published": published,
            "published_year": [p.year for p in published],
            "filer": filer,
            "filer_type": ["vendor" if i % 3 else "open source project" for i in range(n)],
        }
    ).write_parquet(root / "data/sets" / sets.inputs_name("test"))
    pairs = [[{"vendor": f"Vendor{i % 25}", "product": "door"}] for i in range(n)]
    pl.DataFrame({"cve_id": ids, "split": ["test"] * n, "filer_pairs": pairs}).write_parquet(
        root / "data/sets" / sets.product_inputs_name("test")
    )
    products = [[f"vendor{i % 25}:door"] if i % 5 else None for i in range(n)]
    pl.DataFrame(
        {"cve_id": ids, "split": ["test"] * n, "nvd_products": products},
        schema={"cve_id": pl.String, "split": pl.String, "nvd_products": pl.List(pl.String)},
    ).write_parquet(root / "data/sets" / sets.product_labels_name("test"))
    for model, skill, name in (
        ("fallback", 0.6, "test_probabilities"),
        ("fallback", 0.1, "test_text_probabilities"),
        ("floors", 0.25, "test_probabilities"),
    ):
        columns: dict[str, object] = {"cve_id": ids}
        p = probabilities(rng, [b or "LOW" for b in band], BANDS, skill)
        for j, b in enumerate(BANDS):
            columns[f"band__{b}"] = p[:, j]
        for m, values in METRICS.items():
            p = probabilities(rng, [str(v) for v in labels[f"nvd_{m}"]], values, skill)  # type: ignore[union-attr]
            for j, v in enumerate(values):
                columns[f"metric_{m}__{v}"] = p[:, j]
        p = probabilities(rng, [str(c) for c in labels["cwe"]], CWES, skill)  # type: ignore[union-attr]
        for j, c in enumerate(CWES):
            columns[f"cwe__{c}"] = p[:, j]
        pl.DataFrame(columns).write_parquet(root / f"data/models/{model}/{name}.parquet")
    score = rng.random(n) * 0.2 + kev * 0.5
    pl.DataFrame(
        {"cve_id": ids, "exploit_lgbm": score, "exploit_floor": rng.random(n) * 0.5 + kev * 0.2}
    ).write_parquet(root / "data/models/rank/test_scores.parquet")
    surv = {"cve_id": ids}
    for model in ("cox", "forest"):
        for h in (30, 90, 180):
            surv[f"{model}_listed_by_{h}"] = (score * h / 180).astype(np.float32)  # type: ignore[assignment]
    pl.DataFrame(surv).write_parquet(root / "data/models/survival/test_survival.parquet")
    keys = [[f"vendor{i % 25}:door", "other:thing"] for i in range(n)]
    pl.DataFrame(
        {
            "cve_id": ids,
            "floor_keys": keys,
            "floor_scores": [[100.0, 60.0]] * n,
            "retrieval_keys": [list(reversed(k)) for k in keys],
            "retrieval_scores": [[0.9, 0.8]] * n,
        },
        schema={
            "cve_id": pl.String,
            "floor_keys": pl.List(pl.String),
            "floor_scores": pl.List(pl.Float32),
            "retrieval_keys": pl.List(pl.String),
            "retrieval_scores": pl.List(pl.Float32),
        },
    ).write_parquet(root / "data/models/product/test_candidates.parquet")
    epss = [
        {"cve_id": c, "offset_days": d, "epss": float(e)}
        for c, e in zip(ids, rng.random(n) * 0.3 + kev * 0.2, strict=True)
        for d in (1, 7, 30)
        if not (d == 30 and c.endswith("7"))
    ]
    pl.DataFrame(epss).write_parquet(root / "data/bronze/epss_offsets/part.parquet")
    iso = {"x": [0.0, 0.5, 1.0], "y": [0.0, 0.2, 0.7]}
    calibration = {"exploitation": {"exploit_lgbm": {"map": iso}, "exploit_floor": {"map": iso}}}
    (root / "results/models/calibration.json").write_text(json.dumps(calibration), encoding="utf-8")
    digest = hashlib.sha256(json.dumps(iso, sort_keys=True).encode()).hexdigest()
    heads = {"band": 1.1, "cwe": 1.0, **{f"metric_{m}": 1.0 for m in METRICS}}
    from scripts.choose_operating_points import TEST_FILES

    points = {
        "primary": {
            "fill": "fallback",
            "fill_design": "joint",
            "fill_comparator": "floors",
            "exploitation": "exploit_lgbm",
            "exploitation_comparator": "exploit_floor",
        },
        "temperatures": {"fallback": heads, "floors": heads},
        "isotonic_maps_sha256": {"exploit_lgbm": digest, "exploit_floor": digest},
        "conformal": {
            "target": 0.9,
            "cutoffs": {h: 0.85 for h in heads if h != "cwe"},
            "floor_band_cutoff": 0.85,
        },
        "c2": {
            "top_share": 0.05,
            "rank_by": "the raw exploit_lgbm score",
            "population": "test window CVEs, Q03 left out",
        },
        "product_floor_threshold": 80,
        "test_predictions": {
            name: sets.content_digest(root / "data/models" / path) for name, path in TEST_FILES.items()
        },
    }
    (root / "config/operating_points.yaml").write_text(yaml.safe_dump(points), encoding="utf-8")
    (root / "evaluation/registration.json").write_text(
        json.dumps({"stages": [{"stage": "models"}, {"stage": "operating_points"}]}), encoding="utf-8"
    )
    (root / "results/models/sets.json").write_text(
        json.dumps({"lake_cut": "2026-11-13T06:00:00+00:00"}), encoding="utf-8"
    )


def test_the_scorer_runs_end_to_end_once(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    write_root(tmp_path)
    monkeypatch.setattr(score_test, "plan_seed", lambda _root: 20261114)
    monkeypatch.setattr(score_test, "RESAMPLES", 200)
    args = [
        "--models",
        str(tmp_path / "data/models"),
        "--sets",
        str(tmp_path / "data/sets"),
        "--bronze",
        str(tmp_path / "data/bronze"),
    ]
    assert score_test.main(args, root=tmp_path) == 0
    c1 = json.loads((tmp_path / "results/models/c1.json").read_text(encoding="utf-8"))
    assert c1["kappa"]["model"]["value"] > c1["kappa"]["floor"]["value"]
    assert c1["verdict"] in {"met", "not met"} and len(c1["reliability"]) > 0
    c2 = json.loads((tmp_path / "results/models/c2.json").read_text(encoding="utf-8"))
    assert {"model", "floor", "epss_day_1", "epss_day_7", "epss_day_30"} <= set(c2["recall_at_top5"])
    assert c2["recall_at_top5"]["model_minus_floor"]["reading"] in {"tie", "ahead", "behind"}
    scoring = json.loads((tmp_path / "results/models/test_scoring.json").read_text(encoding="utf-8"))
    assert set(scoring["secondary"]["fill"]) == {"fallback", "fallback_text", "floors"}
    assert "band_from_metrics" in scoring["secondary"]["fill"]["fallback"]
    assert set(scoring["slices"]["fill"]) == {"filer", "filer_type", "cwe", "vendor", "published_year"}
    part = json.loads((tmp_path / "results/parts/test.json").read_text(encoding="utf-8"))
    assert "models.test.c1.kappa" in part["values"] and "models.test.slices.fill.filer" in part["tables"]
    assert "models.test.fill.fallback_text.band.qwk" in part["values"]
    assert part["values"]["criteria.c1.verdict"]["value"] == c1["verdict"]
    assert "models.test.c2.difference_floor_low" in part["values"]
    # A second run is refused: test is scored once.
    try:
        score_test.main(args, root=tmp_path)
    except SystemExit as err:
        assert "scored already" in str(err)
    else:
        raise AssertionError("a second scoring ran")
    # The recheck scores again from the same frozen files, finds every number equal, and changes
    # no result; a changed committed number is found.
    before = (tmp_path / "results/models/c1.json").read_bytes()
    assert score_test.main([*args, "--recheck"], root=tmp_path) == 0
    assert (tmp_path / "results/models/c1.json").read_bytes() == before
    assert (
        json.loads((tmp_path / "results/models/test_recheck.json").read_text(encoding="utf-8"))["result"]
        == "pass"
    )
    c1["kappa"]["model"]["value"] += 0.001
    (tmp_path / "results/models/c1.json").write_text(json.dumps(c1), encoding="utf-8")
    assert score_test.main([*args, "--recheck"], root=tmp_path) == 1
    found = json.loads((tmp_path / "results/models/test_recheck.json").read_text(encoding="utf-8"))
    assert found["difference_count"] == 1 and found["differences"][0].startswith(".c1.kappa.model.value")
