"""The ONNX exports: the API's featurizer equals scikit-learn's, the linear graph equals the floor,
the LightGBM graph equals the booster, all on plain rows as the API builds them."""

from __future__ import annotations

from datetime import UTC, datetime

import lightgbm as lgb
import numpy as np
import polars as pl
import pytest
from unscheduled_core import featurize
from unscheduled_models import export, floors, rank
from unscheduled_models.features import Features

from tests.models.test_floors import frame
from tests.models.test_rank import rank_frame


def with_rare_values(f: pl.DataFrame) -> pl.DataFrame:
    """Filer values seen once (the infrequent bucket), an empty one, a CWE list, and text with
    punctuation, digits, accents and doubled spaces for the analyzers."""
    n = f.height
    return f.with_columns(
        pl.Series(
            "filer",
            [
                f"rare-{i}" if i % 11 == 0 else ("" if i % 13 == 0 else v)
                for i, v in enumerate(f.get_column("filer"))
            ],
        ),
        pl.Series(
            "text",
            [
                f"{t}  Café v2.1 (x86_64)\tCVE-2024-0001; the  état" if i % 3 == 0 else t
                for i, t in enumerate(f.get_column("text"))
            ],
        ),
        pl.Series(
            "filer_cvss31_vector",
            [None if i % 2 else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" for i in range(n)],
        ),
    )


@pytest.mark.parametrize("variant", ["word", "word_char"])
def test_the_api_featurizer_equals_scikit_learn(variant: str) -> None:
    train = with_rare_values(frame(400, 1))
    dev = with_rare_values(frame(120, 2, "development")).with_columns(
        pl.Series("filer", ["never-seen"] * 60 + ["acme"] * 60)
    )
    features = Features(variant)
    features.fit_transform(train)
    spec = export.floor_spec(features)
    built = featurize.FloorFeatures(spec)
    assert built.width == features.transform(dev).shape[1]
    native = features.transform(dev).toarray()
    dense = np.zeros_like(native)
    for i, row in enumerate(dev.to_dicts()):
        for j, v in built.transform(row).items():
            dense[i, j] = v
    assert np.max(np.abs(native - dense)) < 1e-6


def test_the_linear_graph_equals_the_floor_for_many_classes_and_two() -> None:
    train, dev = frame(500, 3), frame(150, 4, "development")
    features = Features("word")
    x = features.fit_transform(train)
    spec = export.floor_spec(features)
    for label in ("band", "nvd_AV"):
        rows = floors.labelled(train, label)
        model, _ = floors.fit(x[rows], floors.labels_at(train, label, rows), 1.0, 7)
        classes = [str(c) for c in model.classes_]
        graph = export.linear_onnx(model.estimators_, classes, x.shape[1], label)
        result = export.floor_parity(model, features, dev, spec, graph)
        assert result["max_feature_difference"] < 1e-6
        assert result["max_probability_difference"] < export.TOLERANCE


def test_the_lightgbm_graph_equals_the_booster() -> None:
    train = rank_frame(2500, 4, datetime(2021, 5, 7, tzinfo=UTC), 900)
    dev = rank_frame(600, 5, datetime(2024, 1, 1, tzinfo=UTC), 300, "development")
    rng = np.random.default_rng(1)
    train = rank.with_projection(train, rng.dirichlet(np.ones(4), train.height))
    dev = rank.with_projection(dev, rng.dirichlet(np.ones(4), dev.height))
    design = rank.DayZero().fit(train)
    x = design.dense(train)
    params = {"objective": "binary", "num_leaves": 15, "verbose": -1, "deterministic": True, "seed": 1}
    data = lgb.Dataset(x, rank.truth(train), categorical_feature=design.categorical_indices())
    booster = lgb.train(params, data, num_boost_round=60)
    spec = export.day0_spec(design)
    graph = export.lgbm_onnx(booster, x.shape[1])
    result = export.lgbm_parity(booster, design, dev, spec, graph)
    assert result["max_input_difference"] == 0.0
    assert result["max_probability_difference"] < export.TOLERANCE


def test_the_cvss_formula_matches_the_library() -> None:
    from unscheduled_lake.cvss import check

    rng = np.random.default_rng(2)
    choices = {
        "AV": "NALP",
        "AC": "LH",
        "PR": "NLH",
        "UI": "NR",
        "S": "UC",
        "C": "HLN",
        "I": "HLN",
        "A": "HLN",
    }
    for _ in range(300):
        metrics = {m: str(rng.choice(list(v))) for m, v in choices.items()}
        vector = "CVSS:3.1/" + "/".join(f"{m}:{v}" for m, v in metrics.items())
        assert featurize.cvss31_metrics(vector) == metrics
        assert featurize.cvss31_score(metrics) == check("3.1", vector).base_score, vector
    assert featurize.cvss31_score({"AV": "N"}) is None
    assert featurize.severity(9.8) == "CRITICAL" and featurize.severity(0.0) == "NONE"
