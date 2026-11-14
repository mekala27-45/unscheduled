"""The exploitation models: the population, the out of fold projection, the design and the searches."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import polars as pl
import pytest
from unscheduled_models import rank

from scripts import train_rank
from tests.models.test_floors import frame as fill_frame


def rank_frame(n: int, seed: int, start: datetime, days: int, split: str = "train") -> pl.DataFrame:
    """Fill rows with the rank columns beside: CVEs published over `days` from `start`, listed in KEV
    within 180 days mostly when exploit code was seen by day 0."""
    rng = np.random.default_rng(seed)
    base = fill_frame(n, seed, split)
    published = [
        start + timedelta(days=int(d), hours=int(h))
        for d, h in zip(rng.integers(0, days, n), rng.integers(0, 24, n), strict=True)
    ]
    code = rng.random(n) < 0.1
    listed = code & (rng.random(n) < 0.6) | (rng.random(n) < 0.005)
    return base.with_columns(
        pl.Series("published", published, dtype=pl.Datetime("us", "UTC")),
        pl.Series("published_year", [p.year for p in published], dtype=pl.Int64),
        pl.Series("published_month", [p.year * 12 + p.month for p in published], dtype=pl.Int64),
        pl.Series("reserved_to_published_days", rng.integers(0, 90, n), dtype=pl.Int64),
        pl.Series("affected_entries", rng.integers(0, 4, n), dtype=pl.Int64),
        pl.Series("vendor_present", rng.random(n) < 0.9),
        pl.Series("product_present", rng.random(n) < 0.9),
        pl.Series("versions_present", rng.random(n) < 0.8),
        pl.Series("exploit_code_by_day0", code),
        pl.Series("kev_180", listed),
        pl.Series("kev_q03", [i == 0 for i in range(n)]),
    )


def test_recall_at_the_top_counts_a_share_of_the_population() -> None:
    truth = np.array([1, 0, 0, 0, 1, 0, 0, 0, 0, 0] * 4)
    score = np.linspace(1, 0, 40)
    # The first two of forty (5 percent) are a positive and a negative: one of eight positives.
    assert rank.recall_at_top(truth, score) == pytest.approx(1 / 8)
    assert np.isnan(rank.recall_at_top(np.zeros(5), np.ones(5)))
    # A tie at the boundary is broken by position, so the result does not depend on the sort.
    assert rank.recall_at_top(np.array([0, 1] + [0] * 18), np.ones(20)) == 0.0


def test_the_population_starts_with_kev_and_leaves_q03_out() -> None:
    spanning = rank_frame(200, 1, datetime(2021, 1, 1, tzinfo=UTC), 300)
    kept = rank.population(spanning)
    assert 0 < kept.height < spanning.height
    assert kept.get_column("published").dt.date().min() >= rank.RANK_START
    assert not kept.get_column("kev_q03").any()


def test_the_projection_is_out_of_fold_where_the_floor_was_fit() -> None:
    train = rank_frame(400, 2, datetime(2021, 6, 1, tzinfo=UTC), 900)
    train = train.with_columns(
        pl.when(pl.int_range(pl.len()) % 4 == 0).then(None).otherwise(pl.col("band")).alias("band")
    )
    dev = rank_frame(100, 3, datetime(2024, 1, 1, tzinfo=UTC), 300, "development")
    out = rank.band_projection(train, {"development": dev}, "word", 1.0, 7, log=lambda _: None)
    assert out["train"].shape == (400, 4) and out["development"].shape == (100, 4)
    assert np.allclose(out["train"].sum(axis=1), 1.0, atol=1e-6)
    again = rank.band_projection(train, {"development": dev}, "word", 1.0, 7, log=lambda _: None)
    assert np.array_equal(out["train"], again["train"])
    # With the floors step's own floor, every row outside the folds is projected by that floor, the
    # one the API serves, column for column in BANDS order.
    from unscheduled_models import floors
    from unscheduled_models.features import Features

    feats = Features("word")
    x = feats.fit_transform(train)
    rows = floors.labelled(train, "band")
    model, _ = floors.fit(x[rows], floors.labels_at(train, "band", rows), 1.0, 7)
    served = rank.band_projection(
        train, {"development": dev}, "word", 1.0, 7, log=lambda _: None, committed=(feats, model)
    )
    order = [list(model.classes_).index(b) for b in rank.BANDS]
    assert np.array_equal(served["development"], model.predict_proba(feats.transform(dev))[:, order])
    unlabelled = np.setdiff1d(np.arange(train.height), rows)
    assert np.array_equal(served["train"][unlabelled], model.predict_proba(x[unlabelled])[:, order])


def design_frames() -> tuple[pl.DataFrame, pl.DataFrame]:
    train = rank_frame(3000, 4, datetime(2021, 5, 7, tzinfo=UTC), 970)
    dev = rank_frame(800, 5, datetime(2024, 1, 1, tzinfo=UTC), 360, "development")
    zeros = np.full((train.height, 4), 0.25)
    return rank.with_projection(train, zeros), rank.with_projection(dev, np.full((dev.height, 4), 0.25))


def test_the_design_has_one_name_per_dense_column_and_codes_unknowns_as_missing() -> None:
    train, dev = design_frames()
    design = rank.DayZero().fit(rank.population(train))
    dense = design.dense(dev.with_columns(pl.lit("never-seen").alias("filer")))
    assert dense.shape[1] == len(design.names())
    filer = design.names().index("filer")
    assert np.isnan(dense[:, filer]).all()
    assert design.sparse(dev).shape[0] == dev.height


def test_the_searches_find_the_signal_and_repeat() -> None:
    train, dev = design_frames()
    train, dev = rank.population(train), rank.population(dev)
    design = rank.DayZero().fit(train)
    floor = rank.fit_floor_search(design, train, dev, 7, choices=(0.3, 3.0))
    assert floor.dev["auroc"] > 0.75 and len(floor.search) == 2
    first = rank.fit_lgbm_search(design, train, 7, trials=2, threads=1, log=lambda _: None)
    second = rank.fit_lgbm_search(design, train, 7, trials=2, threads=1, log=lambda _: None)
    assert first.params == second.params and first.trees == second.trees
    assert [f["validate_positives"] for f in first.folds] == [f["validate_positives"] for f in second.folds]
    assert np.array_equal(first.model.predict(design.dense(dev)), second.model.predict(design.dense(dev)))


def test_the_script_needs_the_floors_first(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="the floors come first"):
        train_rank.band_floor(tmp_path)
    (tmp_path / "results" / "models").mkdir(parents=True)
    (tmp_path / "results" / "models" / "floors.json").write_text(
        json.dumps({"sample": 100}), encoding="utf-8"
    )
    with pytest.raises(SystemExit, match="sample run"):
        train_rank.band_floor(tmp_path)


def test_smoke_options_need_a_sample() -> None:
    with pytest.raises(SystemExit, match="smoke run"):
        train_rank.main(["--trials", "2"])
