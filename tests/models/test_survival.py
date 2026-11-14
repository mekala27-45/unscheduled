"""The time to KEV models: the design rules, the horizons, the R comparison and its tolerances."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import polars as pl
import pytest
from unscheduled_models import rank, survival

from scripts import train_survival
from tests.models.test_rank import rank_frame

ROOT = Path(__file__).resolve().parents[2]


def survival_frame(n: int, seed: int, start: datetime, days: int, split: str = "train") -> pl.DataFrame:
    """Rank rows with a time to listing: exploit code by day 0 lists sooner, the rest are censored
    at the cut or listed late."""
    rng = np.random.default_rng(seed)
    base = rank_frame(n, seed, start, days, split)
    code = base.get_column("exploit_code_by_day0").to_numpy()
    listed = (code & (rng.random(n) < 0.7)) | (rng.random(n) < 0.03)
    days_to = np.where(code, rng.integers(0, 60, n), rng.integers(30, 900, n))
    censor = rng.integers(400, 1500, n)
    return base.with_columns(
        pl.Series("kev_event", listed & (days_to <= censor)),
        pl.Series("days_to_kev", np.where(listed & (days_to <= censor), days_to, censor), dtype=pl.Int64),
    )


def test_the_design_leaves_out_rare_and_twin_columns() -> None:
    train = survival_frame(3000, 1, datetime(2021, 6, 1, tzinfo=UTC), 900)
    twin = train.with_columns(pl.col("vendor_present").alias("product_present"))
    design = survival.Design().fit(rank.population(twin))
    assert "product_present" not in design.columns
    assert "correlated" in design.dropped["product_present"]
    assert "exploit_code_by_day0" in design.columns
    assert design.dropped["adp_band"].startswith("one category")
    matrix = design.matrix(rank.population(twin))
    assert list(matrix.columns) == design.columns
    assert abs(float(matrix["published_month"].mean())) < 1e-6


def test_a_column_few_listings_touch_is_left_out() -> None:
    train = rank.population(survival_frame(3000, 2, datetime(2021, 6, 1, tzinfo=UTC), 900))
    rare = train.with_columns((pl.int_range(pl.len()) < 30).alias("versions_present"))
    rare = rare.with_columns(
        pl.when(pl.col("versions_present")).then(False).otherwise(pl.col("kev_event")).alias("kev_event")
    )
    design = survival.Design().fit(rare)
    assert "versions_present" not in design.columns
    assert "listings" in design.dropped["versions_present"]


def test_the_models_rank_the_signal_and_their_horizons_rise() -> None:
    train = rank.population(survival_frame(3000, 3, datetime(2021, 6, 1, tzinfo=UTC), 900))
    dev = rank.population(survival_frame(1000, 4, datetime(2024, 1, 1, tzinfo=UTC), 360, "development"))
    result = survival.search(train, dev, 7, 1, penalizers=(0.1,), leaves=(30,), log=lambda _: None)
    x = result.design.matrix(dev)
    cox = survival.cox_listing(result.cox, x)
    forest = survival.forest_listing(result.forest, x)
    for listing in (cox, forest):
        assert listing.shape == (dev.height, len(survival.HORIZONS))
        assert np.all(np.diff(listing, axis=1) >= -1e-9) and listing.min() >= 0 and listing.max() <= 1
    c = survival.concordance(survival.duration(dev), survival.event(dev), survival.cox_risk(result.cox, x))
    assert c > 0.6


def test_the_r_comparison_holds_both_tolerances() -> None:
    train = rank.population(survival_frame(3000, 5, datetime(2021, 6, 1, tzinfo=UTC), 900))
    design = survival.Design().fit(train)
    model = survival.fit_cox(design.matrix(train), survival.duration(train), survival.event(train), 0.0)
    same = {"coefficients": dict(model.params_), "concordance": model.concordance_index_}
    assert survival.compare_with_r(model, same, 0.001, 0.002)["result"] == "pass"
    shifted = {**same, "coefficients": {k: v + 0.01 for k, v in same["coefficients"].items()}}
    assert survival.compare_with_r(model, shifted, 0.001, 0.002)["result"] == "fail"
    short = {**same, "coefficients": dict(list(same["coefficients"].items())[1:])}
    assert survival.compare_with_r(model, short, 0.001, 0.002)["result"] == "fail"


def test_the_tolerances_come_from_the_plan() -> None:
    assert train_survival.r_tolerances(ROOT) == (0.001, 0.002)


def test_the_r_design_ends_with_the_time_and_the_event() -> None:
    train = rank.population(survival_frame(500, 6, datetime(2021, 6, 1, tzinfo=UTC), 900))
    design = survival.Design().fit(train)
    frame = survival.r_design(design, train)
    assert list(frame.columns[-2:]) == ["duration", "event"]
    assert frame["duration"].min() >= 1


@pytest.mark.skipif(not __import__("shutil").which("Rscript"), reason="R runs in the models workflow")
def test_r_agrees_with_lifelines(tmp_path: Path) -> None:
    train = rank.population(survival_frame(3000, 7, datetime(2021, 6, 1, tzinfo=UTC), 900))
    design = survival.Design().fit(train)
    model = survival.fit_cox(design.matrix(train), survival.duration(train), survival.event(train), 0.0)
    result = train_survival.run_r_check(tmp_path, design, train)
    assert survival.compare_with_r(model, result, 0.001, 0.002)["result"] == "pass"
