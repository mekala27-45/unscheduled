"""The fill floors: TF-IDF and logistic regression per task, fit on train, chosen on development.

The band floor chooses the text representation and C together (word grams against word and
character grams, C over CHOICES_C) by quadratic weighted kappa on development; the metric and CWE
floors take the chosen representation and choose C by Cohen kappa and by macro F1
(evaluation/phase2_plan.yaml: band_floor, metrics_floor, cwe_floor). Ties go to the earlier choice
in the grid: the smaller C, and word grams before word and character grams.

Every floor is one logistic regression per class against the rest, fit by liblinear. The joint
softmax fit by L-BFGS took more than ten times as long on a sample of train (DECISIONS.md,
2026-11-14, the floor solver), and the plan names logistic regression without the solver. The
class probabilities are the per class probabilities scaled to sum to one, which step nine
calibrates. Fits run in threads, since liblinear releases the GIL, with at most a set number of
CWE fits at once to bound memory; a fit does not depend on the thread it ran in, so the result is
the same for any number of threads.

The test labels are never read here: test and shadow get probabilities, which scripts/score_test.py
judges once.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import polars as pl
from scipy import sparse
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, cohen_kappa_score, confusion_matrix, f1_score
from sklearn.multiclass import OneVsRestClassifier

from unscheduled_models.features import VARIANTS, Features
from unscheduled_models.sets import BANDS, METRICS

CHOICES_C = (0.1, 0.3, 1.0, 3.0, 10.0)
MAX_ITER = 1000
SOLVER = "liblinear, one logistic regression per class against the rest"
VARIANT_NAMES = {"word": "word grams", "word_char": "word and character grams"}


@dataclass(frozen=True)
class Task:
    name: str
    label: str
    metric: str  # qwk, kappa or macro_f1


TASKS = (
    Task("band", "band", "qwk"),
    *(Task(f"metric_{m}", f"nvd_{m}", "kappa") for m in METRICS),
    Task("cwe", "cwe", "macro_f1"),
)
HEAVY_TASKS = frozenset({"cwe"})


def score(metric: str, truth: list[str], predicted: list[str]) -> float:
    if metric == "qwk":
        # NONE sits below LOW: no band head predicts it, but a band rated from predicted metrics can.
        order = {"NONE": -1, **{b: i for i, b in enumerate(BANDS)}}
        return float(
            cohen_kappa_score([order[t] for t in truth], [order[p] for p in predicted], weights="quadratic")
        )
    if metric == "kappa":
        return float(cohen_kappa_score(truth, predicted))
    if metric == "macro_f1":
        return float(f1_score(truth, predicted, average="macro", zero_division=0))
    raise ValueError(f"unknown metric {metric!r}")


def labelled(frame: pl.DataFrame, label: str) -> np.ndarray:
    """The positions of the rows that carry the label (a non empty value)."""
    values = frame.get_column(label).cast(pl.String)
    mask = values.is_not_null() & (values.fill_null("") != "")
    return np.flatnonzero(mask.to_numpy())


def labels_at(frame: pl.DataFrame, label: str, rows: np.ndarray) -> list[str]:
    values = frame.get_column(label).cast(pl.String).to_list()
    return [str(values[i]) for i in rows]


def fit(x: sparse.csr_matrix, y: list[str], c: float, seed: int) -> tuple[OneVsRestClassifier, int]:
    """One fit of a floor; returns the model and the most iterations any of its classes took."""
    model = OneVsRestClassifier(
        LogisticRegression(C=c, solver="liblinear", max_iter=MAX_ITER, random_state=seed)
    )
    model.fit(x, np.asarray(y))
    iterations = max(int(np.max(e.n_iter_)) for e in model.estimators_)
    return model, iterations


def predicted(model: OneVsRestClassifier, proba: np.ndarray) -> list[str]:
    return [str(v) for v in model.classes_[np.argmax(proba, axis=1)]]


def evaluate(model: OneVsRestClassifier, x: sparse.csr_matrix, y: list[str], metric: str) -> dict[str, float]:
    proba = model.predict_proba(x)
    guess = predicted(model, proba)
    out = {
        metric: score(metric, y, guess),
        "accuracy": float(accuracy_score(y, guess)),
        "macro_f1": score("macro_f1", y, guess),
    }
    if len(model.classes_) > 5:
        top5 = np.argsort(-proba, axis=1)[:, :5]
        classes = [str(v) for v in model.classes_]
        out["top5_accuracy"] = float(np.mean([y[i] in {classes[j] for j in top5[i]} for i in range(len(y))]))
    return out


@dataclass
class Fitted:
    task: Task
    variant: str
    c: float
    model: OneVsRestClassifier
    dev: dict[str, float]
    seconds: float
    iterations: int

    @property
    def value(self) -> float:
        return self.dev[self.task.metric]

    def row(self) -> dict[str, Any]:
        return {
            "task": self.task.name,
            "variant": self.variant,
            "C": self.c,
            **{k: round(v, 6) for k, v in self.dev.items()},
            "seconds": round(self.seconds, 1),
            "iterations": self.iterations,
            "converged": self.iterations < MAX_ITER,
        }


@dataclass(frozen=True)
class Job:
    task: Task
    c: float

    @property
    def heavy(self) -> bool:
        return self.task.name in HEAVY_TASKS


def run_jobs(jobs: list[Job], run: Callable[[Job], Fitted], workers: int, heavy: int) -> list[Fitted]:
    """Run the jobs on `workers` threads with at most `heavy` heavy jobs at once: a thread that
    would wait for a heavy slot takes the next light job instead. The results come back in the
    order of the jobs, whatever order they ran in."""
    condition = threading.Condition()
    pending = list(enumerate(jobs))
    running_heavy = 0
    results: dict[int, Fitted] = {}
    failures: list[BaseException] = []
    limit = max(1, heavy)

    def take() -> tuple[int, Job] | None:
        nonlocal running_heavy
        with condition:
            while pending and not failures:
                for k, (index, job) in enumerate(pending):
                    if not job.heavy or running_heavy < limit:
                        del pending[k]
                        running_heavy += int(job.heavy)
                        return index, job
                condition.wait()
            return None

    def finish(job: Job) -> None:
        nonlocal running_heavy
        with condition:
            running_heavy -= int(job.heavy)
            condition.notify_all()

    def worker() -> None:
        while (item := take()) is not None:
            index, job = item
            try:
                results[index] = run(job)
            except BaseException as error:  # re-raised in the caller once every thread stops
                with condition:
                    failures.append(error)
            finally:
                finish(job)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, workers))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if failures:
        raise failures[0]
    return [results[i] for i in range(len(jobs))]


@dataclass
class Design:
    """One text representation fit on train: the train and development matrices, and the rows of
    train each label covers, sliced once and shared by every fit of that label."""

    variant: str
    train: pl.DataFrame
    dev: pl.DataFrame
    features: Features = field(init=False)
    x_train: sparse.csr_matrix = field(init=False)
    x_dev: sparse.csr_matrix = field(init=False)
    seconds: float = field(init=False)
    _slices: dict[bytes, sparse.csr_matrix] = field(init=False, default_factory=dict)
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock)

    def __post_init__(self) -> None:
        started = time.monotonic()
        self.features = Features(self.variant)
        self.x_train = self.features.fit_transform(self.train)
        self.x_dev = self.features.transform(self.dev)
        self.seconds = time.monotonic() - started

    def data(self, task: Task) -> tuple[sparse.csr_matrix, list[str], sparse.csr_matrix, list[str]]:
        rows, dev_rows = labelled(self.train, task.label), labelled(self.dev, task.label)
        key = rows.tobytes()
        with self._lock:
            if key not in self._slices:
                self._slices[key] = self.x_train[rows]
            x = self._slices[key]
        return (
            x,
            labels_at(self.train, task.label, rows),
            self.x_dev[dev_rows],
            labels_at(self.dev, task.label, dev_rows),
        )


def best(fits: list[Fitted]) -> Fitted:
    """The highest development score; a tie goes to the earlier fit in the grid."""
    top = fits[0]
    for f in fits[1:]:
        if f.value > top.value:
            top = f
    return top


@dataclass
class Search:
    record: dict[str, Any]
    features: Features
    models: dict[str, OneVsRestClassifier]


def search(
    train: pl.DataFrame,
    dev: pl.DataFrame,
    *,
    seed: int,
    variants: tuple[str, ...] = VARIANTS,
    choices: tuple[float, ...] = CHOICES_C,
    workers: int = 1,
    heavy: int = 1,
    log: Callable[[str], None] = print,
) -> Search:
    """The whole search: the representation and C with the band, then C for every other task on
    the chosen representation. `train` and `dev` hold the inputs and labels joined."""
    lock = threading.Lock()

    def say(text: str) -> None:
        with lock:
            log(text)

    def runner(design: Design) -> Callable[[Job], Fitted]:
        def run(job: Job) -> Fitted:
            started = time.monotonic()
            x, y, x_dev, y_dev = design.data(job.task)
            model, iterations = fit(x, y, job.c, seed)
            result = evaluate(model, x_dev, y_dev, job.task.metric)
            done = Fitted(
                job.task, design.variant, job.c, model, result, time.monotonic() - started, iterations
            )
            say(
                f"floors: {job.task.name} {design.variant} C={job.c} dev {job.task.metric} "
                f"{done.value:.4f} in {done.seconds:.0f}s, {iterations} iterations"
            )
            return done

        return run

    band = TASKS[0]
    fitted: list[Fitted] = []
    sizes: dict[str, dict[str, int]] = {}
    seconds: dict[str, float] = {}
    chosen: tuple[Fitted, Design] | None = None
    for variant in variants:
        design = Design(variant, train, dev)
        sizes[variant], seconds[variant] = design.features.size(), round(design.seconds, 1)
        say(f"floors: {variant} features in {design.seconds:.0f}s, {design.x_train.shape[1]} columns")
        fits = run_jobs([Job(band, c) for c in choices], runner(design), workers, heavy)
        fitted.extend(fits)
        top = best(fits)
        if chosen is None or top.value > chosen[0].value:
            chosen = (top, design)
        del design
    assert chosen is not None
    band_fit, design = chosen
    rest = sorted(TASKS[1:], key=lambda t: t.name not in HEAVY_TASKS)
    fits = run_jobs([Job(t, c) for t in rest for c in choices], runner(design), workers, heavy)
    fitted.extend(fits)
    order = {t.name: i for i, t in enumerate(TASKS)}
    fitted.sort(key=lambda f: (order[f.task.name], variants.index(f.variant), choices.index(f.c)))
    models: dict[str, OneVsRestClassifier] = {}
    entries: dict[str, Any] = {}
    for task in TASKS:
        candidates = [f for f in fitted if f.task == task and f.variant == design.variant]
        top = band_fit if task == band else best(candidates)
        models[task.name] = top.model
        entries[task.name] = chosen_entry(top, design, choices)
    record = {
        "solver": SOLVER,
        "max_iter": MAX_ITER,
        "seed": seed,
        "grid": {"variants": list(variants), "C": list(choices)},
        "representation": {"chosen": design.variant, "sizes": sizes, "seconds": seconds},
        "search": [f.row() for f in fitted],
        "chosen": entries,
    }
    return Search(record, design.features, models)


def chosen_entry(fit: Fitted, design: Design, choices: tuple[float, ...] = CHOICES_C) -> dict[str, Any]:
    task = fit.task
    rows, dev_rows = labelled(design.train, task.label), labelled(design.dev, task.label)
    train_labels = labels_at(design.train, task.label, rows)
    entry: dict[str, Any] = {
        "label": task.label,
        "metric": task.metric,
        "variant": fit.variant,
        "C": fit.c,
        # A choice at either end of the grid says the best C may lie past it; the plan fixed the grid.
        "at_grid_edge": fit.c in (min(choices), max(choices)),
        "classes": [str(v) for v in fit.model.classes_],
        "train_rows": len(rows),
        "dev_rows": len(dev_rows),
        "train_classes": {str(k): int(v) for k, v in sorted(_counts(train_labels).items())},
        "dev": {k: round(v, 6) for k, v in fit.dev.items()},
        "iterations": fit.iterations,
        "converged": fit.iterations < MAX_ITER,
    }
    if task.name == "band":
        guess = predicted(fit.model, fit.model.predict_proba(design.x_dev[dev_rows]))
        truth = labels_at(design.dev, task.label, dev_rows)
        entry["dev_confusion"] = {
            "rows_truth_columns_predicted": list(BANDS),
            "matrix": confusion_matrix(truth, guess, labels=list(BANDS)).tolist(),
        }
    return entry


def _counts(values: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


def probabilities(
    features: Features, models: dict[str, OneVsRestClassifier], frame: pl.DataFrame
) -> pl.DataFrame:
    """Per CVE, the probability of every class of every task, for development, test or shadow."""
    x = features.transform(frame)
    columns: dict[str, Any] = {"cve_id": frame.get_column("cve_id")}
    for name, model in models.items():
        proba = model.predict_proba(x).astype(np.float32)
        for j, cls in enumerate(model.classes_):
            columns[f"{name}__{cls}"] = proba[:, j]
    return pl.DataFrame(columns)


def band_from(proba: pl.DataFrame) -> list[str]:
    """The band with the highest probability in a probabilities frame."""
    matrix = proba.select([f"band__{b}" for b in BANDS]).to_numpy()
    return [BANDS[i] for i in np.argmax(matrix, axis=1)]


def severity(score: float) -> str:
    """The CVSS 3.1 qualitative rating of a base score."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0.0 else "NONE"


def band_from_metrics(proba: pl.DataFrame) -> list[str]:
    """The plan's band_from_metrics: the most probable value of each of the eight base metric heads
    written as a CVSS 3.1 vector, scored by the cvss library and rated. Reported beside the band
    head, never the primary (evaluation/phase2_plan.yaml)."""
    from unscheduled_lake.cvss import check

    values = []
    for m in METRICS:
        columns = [c for c in proba.columns if c.startswith(f"metric_{m}__")]
        classes = [c.split("__", 1)[1] for c in columns]
        best = np.argmax(proba.select(columns).to_numpy(), axis=1)
        values.append([classes[i] for i in best])
    cache: dict[str, str] = {}
    out = []
    for row in zip(*values, strict=True):
        vector = "CVSS:3.1/" + "/".join(f"{m}:{v}" for m, v in zip(METRICS, row, strict=True))
        if vector not in cache:
            result = check("3.1", vector)
            cache[vector] = severity(result.base_score) if result.base_score is not None else "NONE"
        out.append(cache[vector])
    return out


def reference(dev: pl.DataFrame, dev_proba: pl.DataFrame) -> dict[str, Any]:
    """The filer band against the NVD band on development rows that have both, the line every band
    comparison draws, beside the band floor on the same rows and on the rows with no filer band."""
    joined = dev.select("cve_id", "band", "filer_band").join(dev_proba, on="cve_id", how="left")
    joined = joined.with_columns(pl.Series("floor_band", band_from(joined), dtype=pl.String))
    labelled_rows = joined.filter(pl.col("band").is_in(list(BANDS)))
    with_filer = labelled_rows.filter(pl.col("filer_band").is_in(list(BANDS)))
    without = labelled_rows.filter(~pl.col("filer_band").is_in(list(BANDS)) | pl.col("filer_band").is_null())

    def qwk(frame: pl.DataFrame, column: str) -> float | None:
        if frame.height == 0:
            return None
        return round(score("qwk", frame.get_column("band").to_list(), frame.get_column(column).to_list()), 6)

    return {
        "with_filer_band": {
            "rows": with_filer.height,
            "filer_qwk": qwk(with_filer, "filer_band"),
            "floor_qwk": qwk(with_filer, "floor_band"),
        },
        "without_filer_band": {"rows": without.height, "floor_qwk": qwk(without, "floor_band")},
        "all": {"rows": labelled_rows.height, "floor_qwk": qwk(labelled_rows, "floor_band")},
    }
