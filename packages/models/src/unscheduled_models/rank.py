"""The exploitation models of Phase 2: will CISA list a CVE in KEV within 180 days of publication,
scored at day 0 (evaluation/phase2_plan.yaml: exploit_floor, exploit_lgbm).

The population is every published CVE from RANK_START on, with the CVEs KEV listed before their
publication (quarantine Q03) left out: KEV began on 3 November 2021, so an earlier CVE could not be
listed within 180 days (DECISIONS.md, 14 November 2026, the change request). The features are the
day 0 features of the plan (the filer values, the CISA values known at day 0, the affected entries,
the exploit code signal, the days from reservation to publication, the publication year and month
as numbers) and the band floor text projection: the four band probabilities of the band floor,
taken out of fold for the train CVEs the band floor was fit on, so a train CVE's projection is never
its own fitted value.

The floor is a logistic regression with balanced class weights, C chosen by average precision on
development. LightGBM takes the same features with the positive class weighted by the ratio of
negatives to positives; Optuna's TPE sampler searches the plan's space for the plan's trial count,
each trial scored by the mean average precision over the three half year folds of the change
request, each fold stopped early at most MAX_TREES trees; the final model is fit on the whole train
population with the best parameters and the mean of the folds' best tree counts.
"""

from __future__ import annotations

import math
import time
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from typing import Any

import lightgbm as lgb
import numpy as np
import optuna
import pandas as pd
import polars as pl
from scipy import sparse
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import KFold
from sklearn.preprocessing import MultiLabelBinarizer, OneHotEncoder, StandardScaler

from unscheduled_models import features as fill_features
from unscheduled_models.floors import fit as fit_floor
from unscheduled_models.floors import labelled, labels_at
from unscheduled_models.sets import BANDS

RANK_START = date(2021, 5, 7)
FOLDS = (
    (date(2022, 7, 1), date(2023, 1, 1)),
    (date(2023, 1, 1), date(2023, 7, 1)),
    (date(2023, 7, 1), date(2024, 1, 1)),
)
LABEL = "kev_180"
NUMERIC = ("reserved_to_published_days", "published_year", "published_month", "affected_entries")
FLAGS = ("vendor_present", "product_present", "versions_present", "exploit_code_by_day0")
CATEGORICAL = fill_features.CATEGORICAL
MULTI = fill_features.MULTI
PROJECTION = tuple(f"band_floor_{b}" for b in BANDS)
MIN_FREQUENCY = fill_features.MIN_FREQUENCY
CHOICES_C = (0.1, 0.3, 1.0, 3.0, 10.0)
MAX_TREES = 2000
EARLY_STOP = 100
PROJECTION_FOLDS = 5
TOP_SHARE = 0.05


def population(frame: pl.DataFrame) -> pl.DataFrame:
    """The rank population of a window: published from RANK_START on, Q03 left out."""
    return frame.filter(
        (pl.col("published").dt.date() >= RANK_START) & ~pl.col("kev_q03").fill_null(False)
    ).sort("cve_id")


def recall_at_top(truth: np.ndarray, score: np.ndarray, share: float = TOP_SHARE) -> float:
    """The share of the positives among the first ceil(share * n) CVEs by score, ties broken by
    position, as C2 counts it on test."""
    n = len(truth)
    positives = int(np.sum(truth))
    if n == 0 or positives == 0:
        return float("nan")
    k = math.ceil(share * n)
    order = np.lexsort((np.arange(n), -score))
    return float(np.sum(truth[order[:k]]) / positives)


def scores(truth: np.ndarray, score: np.ndarray) -> dict[str, float]:
    return {
        "average_precision": float(average_precision_score(truth, score)),
        "auroc": float(roc_auc_score(truth, score)),
        "recall_at_top5": recall_at_top(truth, score),
        "positives": int(np.sum(truth)),
        "rows": len(truth),
    }


def band_projection(
    train: pl.DataFrame,
    others: dict[str, pl.DataFrame],
    variant: str,
    c: float,
    seed: int,
    log: Callable[[str], None] = print,
) -> dict[str, np.ndarray]:
    """The band floor's four band probabilities for every row: out of fold for the train rows with
    an NVD band (the rows the band floor was fit on), from the floor fit on all of them otherwise.
    The columns follow BANDS."""
    started = time.monotonic()
    feats = fill_features.Features(variant)
    x_train = feats.fit_transform(train)
    rows = labelled(train, "band")
    y = np.asarray(labels_at(train, "band", rows))
    full, _ = fit_floor(x_train[rows], list(y), c, seed)
    order = [list(full.classes_).index(b) for b in BANDS]
    out = {"train": full.predict_proba(x_train)[:, order]}
    for k, (fit_idx, held_idx) in enumerate(
        KFold(PROJECTION_FOLDS, shuffle=True, random_state=seed).split(rows)
    ):
        model, _ = fit_floor(x_train[rows[fit_idx]], list(y[fit_idx]), c, seed)
        fold_order = [list(model.classes_).index(b) for b in BANDS]
        out["train"][rows[held_idx]] = model.predict_proba(x_train[rows[held_idx]])[:, fold_order]
        log(f"rank: band projection fold {k + 1} of {PROJECTION_FOLDS} in {time.monotonic() - started:.0f}s")
    for name, frame in others.items():
        out[name] = full.predict_proba(feats.transform(frame))[:, order]
    return out


def with_projection(frame: pl.DataFrame, projection: np.ndarray) -> pl.DataFrame:
    return frame.with_columns(
        [pl.Series(name, projection[:, j].astype(np.float32)) for j, name in enumerate(PROJECTION)]
    )


class DayZero:
    """The day 0 design of the exploitation models, fit on the train population: a sparse matrix for
    the logistic floor (numbers scaled, categories one hot, CWE lists multi hot) and a dense one for
    LightGBM (numbers as they are, categories as codes LightGBM splits on)."""

    def __init__(self) -> None:
        self.scaler = StandardScaler()
        self.onehot = OneHotEncoder(
            handle_unknown="infrequent_if_exist",
            min_frequency=MIN_FREQUENCY,
            sparse_output=True,
            dtype=np.float32,
        )
        self.multi: dict[str, MultiLabelBinarizer] = {}
        self.codes: dict[str, dict[str, int]] = {}

    @staticmethod
    def _numbers(frame: pl.DataFrame) -> np.ndarray:
        return frame.select([pl.col(c).cast(pl.Float64).fill_null(0.0) for c in NUMERIC]).to_numpy()

    @staticmethod
    def _flags(frame: pl.DataFrame) -> np.ndarray:
        return frame.select([pl.col(c).fill_null(False).cast(pl.Float32) for c in FLAGS]).to_numpy()

    @staticmethod
    def _categories(frame: pl.DataFrame) -> list[list[str]]:
        cats = frame.select(
            [
                pl.col(c).cast(pl.String).fill_null(fill_features.NONE).replace("", fill_features.NONE)
                for c in CATEGORICAL
            ]
        )
        return [cats.get_column(c).to_list() for c in CATEGORICAL]

    def _lists(self, frame: pl.DataFrame) -> list[np.ndarray]:
        out = []
        for column in MULTI:
            binarizer = self.multi[column]
            kept = set(binarizer.classes_)
            lists = [
                [v for v in (values or []) if v in kept] for values in frame.get_column(column).to_list()
            ]
            out.append(np.asarray(binarizer.transform(lists), dtype=np.float32))
        return out

    def fit(self, frame: pl.DataFrame) -> DayZero:
        self.scaler.fit(self._numbers(frame))
        columns = self._categories(frame)
        self.onehot.fit(pd.DataFrame(dict(zip(CATEGORICAL, columns, strict=True))))
        for name, values in zip(CATEGORICAL, columns, strict=True):
            counts: dict[str, int] = {}
            for v in values:
                counts[v] = counts.get(v, 0) + 1
            frequent = sorted(v for v, n in counts.items() if n >= MIN_FREQUENCY)
            self.codes[name] = {v: i for i, v in enumerate(frequent)}
        for column in MULTI:
            counts = {}
            for values in frame.get_column(column).to_list():
                for v in values or []:
                    counts[v] = counts.get(v, 0) + 1
            kept = sorted(v for v, n in counts.items() if n >= MIN_FREQUENCY)
            self.multi[column] = MultiLabelBinarizer(classes=kept)
            self.multi[column].fit([kept])
        return self

    def sparse(self, frame: pl.DataFrame) -> sparse.csr_matrix:
        columns = self._categories(frame)
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="Found unknown categories")
            onehot = self.onehot.transform(pd.DataFrame(dict(zip(CATEGORICAL, columns, strict=True))))
        blocks = [
            sparse.csr_matrix(self.scaler.transform(self._numbers(frame)).astype(np.float32)),
            sparse.csr_matrix(self._flags(frame)),
            onehot,
            *(sparse.csr_matrix(b) for b in self._lists(frame)),
            sparse.csr_matrix(frame.select(PROJECTION).to_numpy().astype(np.float32)),
        ]
        matrix = sparse.hstack(blocks, format="csr", dtype=np.float32)
        matrix.sum_duplicates()
        return matrix

    def dense(self, frame: pl.DataFrame) -> np.ndarray:
        columns = self._categories(frame)
        codes = np.array(
            [
                [self.codes[name].get(v, -1) for v in values]
                for name, values in zip(CATEGORICAL, columns, strict=True)
            ],
            dtype=np.float32,
        ).T
        codes[codes < 0] = np.nan
        parts = [
            self._numbers(frame).astype(np.float32),
            self._flags(frame),
            codes,
            *self._lists(frame),
            frame.select(PROJECTION).to_numpy().astype(np.float32),
        ]
        return np.hstack(parts)

    def names(self) -> list[str]:
        lists = [f"{column}={v}" for column in MULTI for v in self.multi[column].classes_]
        return [*NUMERIC, *FLAGS, *CATEGORICAL, *lists, *PROJECTION]

    def categorical_indices(self) -> list[int]:
        start = len(NUMERIC) + len(FLAGS)
        return list(range(start, start + len(CATEGORICAL)))


def predict(model: lgb.Booster, x: np.ndarray) -> np.ndarray:
    """LightGBM's probabilities as one float array."""
    return np.asarray(model.predict(x), dtype=np.float64)


def truth(frame: pl.DataFrame) -> np.ndarray:
    return frame.get_column(LABEL).fill_null(False).cast(pl.Int8).to_numpy()


@dataclass
class FloorResult:
    c: float
    model: LogisticRegression
    search: list[dict[str, Any]]
    dev: dict[str, float]


def fit_floor_search(
    design: DayZero, train: pl.DataFrame, dev: pl.DataFrame, seed: int, choices: tuple[float, ...] = CHOICES_C
) -> FloorResult:
    """The logistic floor: balanced class weights, C by average precision on development; a tie goes
    to the smaller C."""
    x, y = design.sparse(train), truth(train)
    x_dev, y_dev = design.sparse(dev), truth(dev)
    search: list[dict[str, Any]] = []
    best: tuple[float, float, LogisticRegression, dict[str, float]] | None = None
    for c in choices:
        model = LogisticRegression(C=c, class_weight="balanced", max_iter=2000, random_state=seed)
        model.fit(x, y)
        result = scores(y_dev, model.predict_proba(x_dev)[:, 1])
        search.append({"C": c, **{k: round(v, 6) if isinstance(v, float) else v for k, v in result.items()}})
        if best is None or result["average_precision"] > best[0]:
            best = (result["average_precision"], c, model, result)
    assert best is not None
    return FloorResult(best[1], best[2], search, best[3])


def lgbm_params(trial: optuna.Trial | None, fixed: dict[str, Any]) -> dict[str, Any]:
    """The plan's space when a trial asks, or the fixed parameters when the search is over."""
    if trial is None:
        return dict(fixed)
    return {
        "num_leaves": trial.suggest_int("num_leaves", 15, 255),
        "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
        "min_child_samples": trial.suggest_int("min_child_samples", 10, 200),
        "feature_fraction": trial.suggest_float("feature_fraction", 0.5, 1.0),
        "bagging_fraction": trial.suggest_float("bagging_fraction", 0.5, 1.0),
        "lambda_l2": trial.suggest_float("lambda_l2", 0.001, 10.0, log=True),
    }


def base_params(seed: int, threads: int, positive_weight: float) -> dict[str, Any]:
    return {
        "objective": "binary",
        "metric": "average_precision",
        "bagging_freq": 1,
        "scale_pos_weight": positive_weight,
        "seed": seed,
        "deterministic": True,
        "force_row_wise": True,
        "num_threads": threads,
        "verbosity": -1,
    }


@dataclass
class LgbmResult:
    params: dict[str, Any]
    trees: int
    model: lgb.Booster
    trials: list[dict[str, Any]]
    folds: list[dict[str, Any]]


def fit_lgbm_search(
    design: DayZero,
    train: pl.DataFrame,
    seed: int,
    trials: int,
    threads: int,
    log: Callable[[str], None] = print,
) -> LgbmResult:
    x = design.dense(train)
    y = truth(train)
    published = train.get_column("published").dt.date().to_numpy()
    categorical = design.categorical_indices()
    fold_rows = [
        (np.flatnonzero(published < start), np.flatnonzero((published >= start) & (published < end)))
        for start, end in FOLDS
    ]

    def run_folds(params: dict[str, Any]) -> tuple[float, list[int], list[float]]:
        aps, trees = [], []
        for fit_idx, val_idx in fold_rows:
            weight = float((y[fit_idx] == 0).sum() / max(1, (y[fit_idx] == 1).sum()))
            booster = lgb.train(
                {**base_params(seed, threads, weight), **params},
                lgb.Dataset(x[fit_idx], y[fit_idx], categorical_feature=categorical, free_raw_data=False),
                num_boost_round=MAX_TREES,
                valid_sets=[lgb.Dataset(x[val_idx], y[val_idx], categorical_feature=categorical)],
                callbacks=[lgb.early_stopping(EARLY_STOP, verbose=False)],
            )
            trees.append(int(booster.best_iteration))
            aps.append(
                float(
                    average_precision_score(
                        y[val_idx], booster.predict(x[val_idx], num_iteration=booster.best_iteration)
                    )
                )
            )
        return float(np.mean(aps)), trees, aps

    records: list[dict[str, Any]] = []

    def objective(trial: optuna.Trial) -> float:
        params = lgbm_params(trial, {})
        mean_ap, trees, aps = run_folds(params)
        trial.set_user_attr("trees", trees)
        trial.set_user_attr("fold_ap", aps)
        records.append({"trial": trial.number, **params, "mean_ap": mean_ap, "fold_ap": aps, "trees": trees})
        log(f"rank: trial {trial.number + 1} of {trials}, mean fold average precision {mean_ap:.4f}")
        return mean_ap

    optuna.logging.set_verbosity(optuna.logging.WARNING)
    study = optuna.create_study(direction="maximize", sampler=optuna.samplers.TPESampler(seed=seed))
    study.optimize(objective, n_trials=trials)
    best = study.best_trial
    params = lgbm_params(None, best.params)
    trees = max(1, round(float(np.mean(best.user_attrs["trees"]))))
    weight = float((y == 0).sum() / max(1, (y == 1).sum()))
    model = lgb.train(
        {**base_params(seed, threads, weight), **params},
        lgb.Dataset(x, y, categorical_feature=categorical),
        num_boost_round=trees,
    )
    folds = [
        {
            "fit_before": str(start),
            "validate": f"{start} to {end}",
            "fit_rows": len(f),
            "fit_positives": int(y[f].sum()),
            "validate_rows": len(v),
            "validate_positives": int(y[v].sum()),
            "best_trial_ap": round(ap, 6),
            "best_trial_trees": t,
        }
        for (start, end), (f, v), ap, t in zip(
            FOLDS, fold_rows, best.user_attrs["fold_ap"], best.user_attrs["trees"], strict=True
        )
    ]
    return LgbmResult(params, trees, model, records, folds)
