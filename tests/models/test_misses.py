"""The failure taxonomy: misses drawn by seed from development only, every one coded once."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import polars as pl
import pytest
import yaml

from scripts import draw_misses

BANDS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def write(root: Path, n: int = 300) -> None:
    rng = np.random.default_rng(3)
    for folder in ("data/sets", "data/models/fallback", "config", "results/models", "results/parts"):
        (root / folder).mkdir(parents=True, exist_ok=True)
    ids = [f"CVE-2024-{i:05d}" for i in range(n)]
    labels = {
        "cve_id": ids,
        "split": ["development"] * n,
        "band": [BANDS[i % 4] if i % 9 else None for i in range(n)],
        "cwe": ["CWE-79"] * n,
    }
    for m in draw_misses.METRICS:
        labels[f"nvd_{m}"] = ["N"] * n
    pl.DataFrame(labels).write_parquet(root / "data/sets/development_labels.parquet")
    inputs = {
        "cve_id": ids,
        "split": ["development"] * n,
        "published": ["2024-03-01"] * n,
        "description": [f"a flaw number {i}" for i in range(n)],
        "filer": ["acme"] * n,
        "filer_type": ["vendor"] * n,
        "filer_cvss31_vector": [None] * n,
        "filer_cvss30_vector": [None] * n,
        "filer_cvss40_vector": [None] * n,
        "filer_band": [None] * n,
        "filer_cwes": [["CWE-79"]] * n,
        "products": ["acme door"] * n,
        "adp_band": [None] * n,
        "adp_ssvc_exploitation": [None] * n,
    }
    pl.DataFrame(
        inputs,
        schema_overrides={
            "filer_cvss31_vector": pl.String,
            "filer_cvss30_vector": pl.String,
            "filer_cvss40_vector": pl.String,
            "filer_band": pl.String,
            "adp_band": pl.String,
            "adp_ssvc_exploitation": pl.String,
        },
    ).write_parquet(root / "data/sets/development_inputs.parquet")
    proba = rng.dirichlet(np.ones(4), n)
    pl.DataFrame({"cve_id": ids, **{f"band__{b}": proba[:, j] for j, b in enumerate(BANDS)}}).write_parquet(
        root / "data/models/fallback/development_probabilities.parquet"
    )
    calibration = {"primary_fill": "fallback", "fill": {"fallback": {"band": {"temperature": 1.0}}}}
    (root / "results/models/calibration.json").write_text(json.dumps(calibration), encoding="utf-8")
    (root / "results/models/sets.json").write_text(
        json.dumps({"lake_cut": "2026-11-13T06:00:00+00:00"}), encoding="utf-8"
    )


def test_misses_are_drawn_from_development_and_every_one_is_coded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path)
    monkeypatch.setattr(draw_misses, "plan_seed", lambda _root: 20261114)
    args = ["--models", str(tmp_path / "data/models"), "--sets", str(tmp_path / "data/sets")]
    assert draw_misses.main(["draw", *args], root=tmp_path) == 0
    misses = json.loads((tmp_path / "results/models/misses.json").read_text(encoding="utf-8"))
    assert misses["drawn"] == 100 and all(m["predicted_band"] != m["nvd_band"] for m in misses["misses"])
    first = [m["cve_id"] for m in misses["misses"]]
    assert misses["temperature_from"] == "results/models/calibration.json"
    # Frozen operating points take over, with another temperature: the same misses are drawn.
    points = {"primary": {"fill": "fallback"}, "temperatures": {"fallback": {"band": 1.7}}}
    (tmp_path / "config/operating_points.yaml").write_text(yaml.safe_dump(points), encoding="utf-8")
    draw_misses.main(["draw", *args], root=tmp_path)
    again = json.loads((tmp_path / "results/models/misses.json").read_text(encoding="utf-8"))
    assert [m["cve_id"] for m in again["misses"]] == first
    assert again["temperature_from"] == "config/operating_points.yaml"
    codes = {c: ("one band apart" if i % 3 else "the description says little") for i, c in enumerate(first)}
    taxonomy = {
        "categories": [
            {"name": "one band apart", "meaning": "the model and the NVD sit next to each other"},
            {"name": "the description says little", "meaning": "a sentence with no impact named"},
        ],
        "codes": codes,
    }
    (tmp_path / "results/models/taxonomy.json").write_text(json.dumps(taxonomy), encoding="utf-8")
    assert draw_misses.main(["check", *args], root=tmp_path) == 0
    checked = json.loads((tmp_path / "results/models/taxonomy.json").read_text(encoding="utf-8"))
    assert sum(c["count"] for c in checked["categories"]) == 100
    part = json.loads((tmp_path / "results/parts/taxonomy.json").read_text(encoding="utf-8"))
    assert part["values"]["models.taxonomy.drawn"]["value"] == 100
    codes[first[0]] = "a category never named"
    (tmp_path / "results/models/taxonomy.json").write_text(
        json.dumps({**taxonomy, "codes": codes}), encoding="utf-8"
    )
    with pytest.raises(SystemExit, match="unnamed"):
        draw_misses.main(["check", *args], root=tmp_path)
