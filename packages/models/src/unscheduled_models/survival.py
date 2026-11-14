"""The time to a KEV listing, scored at day 0 (evaluation/phase2_plan.yaml: survival_cox, survival_rsf,
survival_r_check).

The population is the rank population (unscheduled_models.rank.population). The time is the days
from publication to the KEV listing, censored at the lake cut, plus one, so a CVE listed on the day
it was published counts at one day and every time is positive. The design is the day 0 features
without the text, coded so a Cox model without a penalty can be fit to it and checked in R: the
numbers (the days from reservation, the publication month, the affected entries) and the flags, and
the low cardinality filer and CISA values one hot against a reference category. A column that fewer
than MIN_EVENTS listings touch is left out, since no fit can estimate it without a penalty, and so
is a column correlated at MAX_CORRELATION or more with one kept before it, which leaves a fit
without a penalty unable to separate the two; the
filer name, the three vectors and the CWE lists, whose one hot columns would be hundreds touched by
a listing or none, are left out for the same reason (DECISIONS.md, 14 November 2026).

The Cox model is lifelines' CoxPHFitter with a ridge penalty chosen by concordance on development;
the forest is scikit-survival's RandomSurvivalForest with 300 trees and the leaf size chosen the same
way. The unpenalized Cox fit on the same design is what the R check compares.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd
import polars as pl
from lifelines import CoxPHFitter
from lifelines.utils import concordance_index
from sksurv.ensemble import RandomSurvivalForest

from unscheduled_models import features as fill_features
from unscheduled_models.sets import METRICS

NUMERIC = {
    "log_reserved_days": pl.col("reserved_to_published_days")
    .cast(pl.Float64)
    .fill_null(0.0)
    .clip(0.0)
    .log1p(),
    "published_month": pl.col("published_month").cast(pl.Float64),
    "log_affected_entries": pl.col("affected_entries").cast(pl.Float64).fill_null(0.0).log1p(),
}
FLAGS = ("vendor_present", "product_present", "versions_present", "exploit_code_by_day0")
CATEGORICAL = (
    "filer_type",
    "filer_band",
    *(f"filer_{m}" for m in METRICS),
    "adp_band",
    "adp_ssvc_exploitation",
    "adp_ssvc_automatable",
    "adp_ssvc_technical_impact",
)
NONE = fill_features.NONE
MIN_FREQUENCY = fill_features.MIN_FREQUENCY
MIN_EVENTS = 5
MAX_CORRELATION = 0.9
PENALIZERS = (0.01, 0.1, 1.0)
LEAF_SIZES = (10, 30, 100)
TREES = 300
HORIZONS = (30, 90, 180)


def duration(frame: pl.DataFrame) -> np.ndarray:
    return frame.get_column("days_to_kev").cast(pl.Float64).to_numpy() + 1.0


def event(frame: pl.DataFrame) -> np.ndarray:
    return frame.get_column("kev_event").fill_null(False).to_numpy().astype(bool)


@dataclass
class Design:
    """The survival design, fit on the train population: which columns, the scale of the numbers,
    and the categories of each coded value."""

    columns: list[str] = field(default_factory=list)
    means: dict[str, float] = field(default_factory=dict)
    scales: dict[str, float] = field(default_factory=dict)
    categories: dict[str, list[str]] = field(default_factory=dict)
    dropped: dict[str, str] = field(default_factory=dict)

    def _raw(self, frame: pl.DataFrame) -> pl.DataFrame:
        numbers = frame.select([expr.alias(name) for name, expr in NUMERIC.items()])
        flags = frame.select([pl.col(c).fill_null(False).cast(pl.Float64) for c in FLAGS])
        coded: list[pl.Series] = []
        for column, values in self.categories.items():
            series = frame.get_column(column).cast(pl.String).fill_null(NONE).replace("", NONE)
            coded.extend((series == v).cast(pl.Float64).alias(f"{column}={v}") for v in values)
        parts = [numbers, flags, *([pl.DataFrame(coded)] if coded else [])]
        return pl.concat(parts, how="horizontal")

    def fit(self, frame: pl.DataFrame) -> Design:
        for column in CATEGORICAL:
            counts = frame.get_column(column).cast(pl.String).fill_null(NONE).replace("", NONE).value_counts()
            frequent = counts.filter(pl.col("count") >= MIN_FREQUENCY).sort(
                ["count", column], descending=[True, False]
            )
            seen: list[str] = [str(v) for v in frequent.get_column(column).to_list()]
            if len(seen) < 2:
                self.dropped[column] = "one category or none seen often enough in train"
                continue
            reference = NONE if NONE in seen else seen[0]
            self.categories[column] = sorted(v for v in seen if v != reference)
        raw = self._raw(frame)
        events = event(frame)
        kept: list[np.ndarray] = []
        for name in raw.columns:
            values: np.ndarray = raw.get_column(name).to_numpy()
            if np.nanstd(values) == 0:
                self.dropped[name] = "constant in train"
            elif name not in NUMERIC and int(events[values > 0].sum()) < MIN_EVENTS:
                self.dropped[name] = f"fewer than {MIN_EVENTS} listings among the rows it marks"
            elif twin := next(
                (
                    c
                    for c, v in zip(self.columns, kept, strict=True)
                    if abs(np.corrcoef(values, v)[0, 1]) >= MAX_CORRELATION
                ),
                None,
            ):
                self.dropped[name] = f"correlated at {MAX_CORRELATION} or more with {twin}, kept before it"
            else:
                self.columns.append(name)
                kept.append(values)
        for name in NUMERIC:
            if name in self.columns:
                numbers = raw.get_column(name).to_numpy()
                self.means[name], self.scales[name] = float(numbers.mean()), float(numbers.std())
        return self

    def matrix(self, frame: pl.DataFrame) -> pd.DataFrame:
        raw = self._raw(frame)
        out = {}
        for name in self.columns:
            values = raw.get_column(name).to_numpy() if name in raw.columns else np.zeros(frame.height)
            if name in self.means:
                values = (values - self.means[name]) / self.scales[name]
            out[name] = values
        return pd.DataFrame(out)


# lifelines' Newton steps start at 0.95 of the full step; on a design with a long tail (a CVE with
# hundreds of affected entries) the first full steps overflow exp and stop the fit. A half step
# reaches the same optimum, the likelihood being concave, and it is the step the R check is held to.
STEP_SIZE = 0.5
MAX_STEPS = 500


def fit_cox(x: pd.DataFrame, durations: np.ndarray, events: np.ndarray, penalizer: float) -> CoxPHFitter:
    data = x.assign(duration=durations, event=events.astype(int))
    model = CoxPHFitter(penalizer=penalizer, l1_ratio=0.0)
    model.fit(
        data,
        duration_col="duration",
        event_col="event",
        fit_options={"step_size": STEP_SIZE, "max_steps": MAX_STEPS},
    )
    return model


def cox_risk(model: CoxPHFitter, x: pd.DataFrame) -> np.ndarray:
    return np.asarray(model.predict_partial_hazard(x), dtype=np.float64).ravel()


def cox_listing(model: CoxPHFitter, x: pd.DataFrame) -> np.ndarray:
    """The probability of a listing by each horizon, one column per horizon."""
    surv = model.predict_survival_function(x, times=[h + 1.0 for h in HORIZONS])
    return 1.0 - np.asarray(surv, dtype=np.float64).T


def concordance(durations: np.ndarray, events: np.ndarray, risk: np.ndarray) -> float:
    """Harrell's concordance: a higher risk should list sooner."""
    return float(concordance_index(durations, -risk, events))


def structured(durations: np.ndarray, events: np.ndarray) -> np.ndarray:
    return np.array(list(zip(events, durations, strict=True)), dtype=[("event", bool), ("time", np.float64)])


def fit_forest(
    x: pd.DataFrame, durations: np.ndarray, events: np.ndarray, leaf: int, seed: int, threads: int
) -> RandomSurvivalForest:
    model = RandomSurvivalForest(
        n_estimators=TREES,
        min_samples_leaf=leaf,
        max_features="sqrt",
        n_jobs=threads,
        random_state=seed,
        low_memory=False,
    )
    model.fit(x.to_numpy(), structured(durations, events))
    return model


def forest_listing(model: RandomSurvivalForest, x: pd.DataFrame) -> np.ndarray:
    surv = model.predict_survival_function(x.to_numpy(), return_array=True)
    times = np.asarray(model.unique_times_)
    out = np.empty((len(x), len(HORIZONS)))
    for j, h in enumerate(HORIZONS):
        k = int(np.searchsorted(times, h + 1.0, side="right")) - 1
        out[:, j] = 0.0 if k < 0 else 1.0 - surv[:, k]
    return out


@dataclass
class SurvivalResult:
    design: Design
    cox: CoxPHFitter
    cox_penalizer: float
    cox_search: list[dict[str, Any]]
    forest: RandomSurvivalForest
    forest_leaf: int
    forest_search: list[dict[str, Any]]
    unpenalized: CoxPHFitter


def search(
    train: pl.DataFrame,
    dev: pl.DataFrame,
    seed: int,
    threads: int,
    penalizers: tuple[float, ...] = PENALIZERS,
    leaves: tuple[int, ...] = LEAF_SIZES,
    log: Callable[[str], None] = print,
) -> SurvivalResult:
    design = Design().fit(train)
    x, d, e = design.matrix(train), duration(train), event(train)
    x_dev, d_dev, e_dev = design.matrix(dev), duration(dev), event(dev)
    cox_search, best_cox = [], None
    for p in penalizers:
        started = time.monotonic()
        model = fit_cox(x, d, e, p)
        c = concordance(d_dev, e_dev, cox_risk(model, x_dev))
        cox_search.append(
            {"penalizer": p, "dev_concordance": round(c, 6), "seconds": round(time.monotonic() - started, 1)}
        )
        log(f"survival: Cox penalizer {p} development concordance {c:.4f}")
        if best_cox is None or c > best_cox[0]:
            best_cox = (c, p, model)
    forest_search, best_forest = [], None
    for leaf in leaves:
        started = time.monotonic()
        model = fit_forest(x, d, e, leaf, seed, threads)
        c = concordance(d_dev, e_dev, np.asarray(model.predict(x_dev.to_numpy()), dtype=np.float64))
        forest_search.append(
            {
                "min_samples_leaf": leaf,
                "dev_concordance": round(c, 6),
                "seconds": round(time.monotonic() - started, 1),
            }
        )
        log(f"survival: forest leaf {leaf} development concordance {c:.4f}")
        if best_forest is None or c > best_forest[0]:
            best_forest = (c, leaf, model)
        else:
            del model
    assert best_cox is not None and best_forest is not None
    unpenalized = fit_cox(x, d, e, 0.0)
    return SurvivalResult(
        design,
        best_cox[2],
        best_cox[1],
        cox_search,
        best_forest[2],
        best_forest[1],
        forest_search,
        unpenalized,
    )


def r_design(design: Design, frame: pl.DataFrame) -> pd.DataFrame:
    """The matrix the R check fits: the design, then the duration and the event."""
    return design.matrix(frame).assign(duration=duration(frame), event=event(frame).astype(int))


def compare_with_r(
    unpenalized: CoxPHFitter, r_result: dict[str, Any], coef_tol: float, conc_tol: float
) -> dict[str, Any]:
    """lifelines unpenalized against R's coxph on the same matrix, within the plan's tolerances."""
    py = {str(k): float(v) for k, v in unpenalized.params_.items()}
    r = {str(k): float(v) for k, v in r_result["coefficients"].items()}
    shared = sorted(set(py) & set(r))
    diffs = {k: abs(py[k] - r[k]) for k in shared}
    conc_py = float(unpenalized.concordance_index_)
    conc_r = float(r_result["concordance"])
    worst = max(diffs.values()) if diffs else float("inf")
    passed = set(py) == set(r) and worst <= coef_tol and abs(conc_py - conc_r) <= conc_tol
    return {
        "columns": len(shared),
        "missing_in_r": sorted(set(py) - set(r)),
        "max_coefficient_difference": worst,
        "concordance_lifelines": conc_py,
        "concordance_r": conc_r,
        "concordance_difference": abs(conc_py - conc_r),
        "coefficient_tolerance": coef_tol,
        "concordance_tolerance": conc_tol,
        "r_version": r_result.get("r_version"),
        "survival_version": r_result.get("survival_version"),
        "result": "pass" if passed else "fail",
    }
