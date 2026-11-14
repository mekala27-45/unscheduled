"""The fill floors: the features, the thread scheduler, the search and the record the script writes."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl
import pytest
from unscheduled_models import floors, sets
from unscheduled_models.features import CATEGORICAL, MIN_FREQUENCY, MULTI, Features, Structured

from scripts import check_test_labels, train_floors

WORDS = {
    "LOW": "information disclosure of version banner",
    "MEDIUM": "cross site scripting in the admin page",
    "HIGH": "sql injection allows reading the database",
    "CRITICAL": "remote code execution without authentication",
}
METRIC_VALUES = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}


def frame(n: int, seed: int, split: str = "train") -> pl.DataFrame:
    """Rows whose band, metrics and CWE follow the words of their text, with filer values beside."""
    rng = np.random.default_rng(seed)
    bands = [sets.BANDS[i] for i in rng.integers(0, 4, size=n)]
    rows: dict[str, list[Any]] = {
        "cve_id": [f"CVE-2024-{seed:02d}{i:05d}" for i in range(n)],
        "split": [split] * n,
        "text": [f"{WORDS[b]} in product {i % 7}\nFiler: acme" for i, b in enumerate(bands)],
        "band": bands,
        "cwe": [
            {"LOW": "CWE-200", "MEDIUM": "CWE-79", "HIGH": "CWE-89", "CRITICAL": "CWE-94"}[b] for b in bands
        ],
    }
    for column in CATEGORICAL:
        rows[column] = [None] * n
    rows["filer"] = ["acme" if i % 3 else "globex" for i in range(n)]
    rows["filer_type"] = ["vendor"] * n
    rows["filer_band"] = [b if i % 2 else None for i, b in enumerate(bands)]
    for column in MULTI:
        rows[column] = [["CWE-79"] if i % 5 == 0 else None for i in range(n)]
    for m, value in METRIC_VALUES.items():
        other = {"N": "L", "L": "H", "H": "L", "U": "C"}[value]
        rows[f"nvd_{m}"] = [value if b in ("HIGH", "CRITICAL") else other for b in bands]
    schema = {c: pl.String for c in rows if c not in MULTI}
    schema.update({c: pl.List(pl.String) for c in MULTI})
    return pl.DataFrame(rows, schema=schema)


def test_features_fit_transform_equals_transform() -> None:
    train = frame(300, 1)
    features = Features("word_char")
    fitted = features.fit_transform(train)
    again = features.transform(train)
    assert fitted.shape == again.shape
    assert (fitted != again).nnz == 0
    assert fitted.has_canonical_format


def test_the_structured_block_is_the_floors_own_and_old_floors_load() -> None:
    train, dev = frame(300, 1), frame(40, 2, "development")
    features = Features("word")
    matrix = features.fit_transform(train)
    block = Structured().fit(train)
    start = len(features.word.vocabulary_)
    assert (matrix[:, start:] != block.transform(train)).nnz == 0
    assert len(block.names()) == matrix.shape[1] - start
    # A floor saved before the block had a class of its own kept its encoders on itself.
    state = dict(features.__dict__)
    kept = state.pop("structured")
    state["onehot"], state["multi"] = kept.onehot, kept.multi
    old = Features.__new__(Features)
    old.__setstate__(state)
    assert (old.transform(dev) != features.transform(dev)).nnz == 0


def test_a_value_train_never_held_encodes_as_zeros() -> None:
    features = Features("word")
    features.fit_transform(frame(300, 1))
    seen = frame(5, 2)  # no CISA band, which train held as one category of its own
    unseen = seen.with_columns(pl.lit("HIGH").alias("adp_band"))
    start = len(features.word.vocabulary_)
    width = len(features.onehot.get_feature_names_out())
    sums_seen = np.asarray(features.transform(seen)[:, start : start + width].sum(axis=1)).ravel()
    sums_unseen = np.asarray(features.transform(unseen)[:, start : start + width].sum(axis=1)).ravel()
    assert np.allclose(sums_seen - sums_unseen, 1.0)


def test_a_cwe_list_value_counts_only_when_train_holds_it_often() -> None:
    train = frame(MIN_FREQUENCY * 5, 3)
    features = Features("word")
    features.fit_transform(train)
    assert list(features.multi["filer_cwes"].classes_) == ["CWE-79"]
    rare = train.with_columns(pl.Series("filer_cwes", [["CWE-1"]] * train.height, dtype=pl.List(pl.String)))
    features_rare = Features("word")
    features_rare.fit_transform(rare.head(MIN_FREQUENCY - 1))
    assert list(features_rare.multi["filer_cwes"].classes_) == []


def test_run_jobs_keeps_the_order_and_the_heavy_limit() -> None:
    lock = threading.Lock()
    state = {"heavy": 0, "most": 0}
    heavy_task, light_task = floors.Task("cwe", "cwe", "macro_f1"), floors.Task("band", "band", "qwk")
    jobs = [floors.Job(heavy_task, c) for c in (1.0, 2.0, 3.0)] + [
        floors.Job(light_task, c) for c in (4.0, 5.0, 6.0)
    ]

    def run(job: floors.Job) -> floors.Fitted:
        if job.heavy:
            with lock:
                state["heavy"] += 1
                state["most"] = max(state["most"], state["heavy"])
        time.sleep(0.05)
        if job.heavy:
            with lock:
                state["heavy"] -= 1
        return floors.Fitted(job.task, "word", job.c, None, {job.task.metric: job.c}, 0.0, 1)

    results = floors.run_jobs(jobs, run, workers=4, heavy=1)
    assert [r.c for r in results] == [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]
    assert state["most"] == 1


def test_run_jobs_raises_a_failure() -> None:
    task = floors.Task("band", "band", "qwk")

    def run(job: floors.Job) -> floors.Fitted:
        raise RuntimeError(f"no fit at {job.c}")

    with pytest.raises(RuntimeError, match="no fit"):
        floors.run_jobs([floors.Job(task, 1.0), floors.Job(task, 2.0)], run, workers=2, heavy=1)


def test_a_tie_goes_to_the_earlier_choice() -> None:
    task = floors.Task("band", "band", "qwk")
    fits = [floors.Fitted(task, "word", c, None, {"qwk": 0.5}, 0.0, 1) for c in (0.1, 0.3)]
    assert floors.best(fits).c == 0.1


def test_the_scores() -> None:
    assert floors.score("qwk", ["LOW", "HIGH"], ["LOW", "HIGH"]) == pytest.approx(1.0)
    assert floors.score("qwk", ["LOW", "CRITICAL"], ["CRITICAL", "LOW"]) < 0
    assert floors.score("macro_f1", ["a", "b"], ["a", "a"]) == pytest.approx(1 / 3)
    with pytest.raises(ValueError, match="unknown metric"):
        floors.score("auc", ["a"], ["a"])


def search(workers: int) -> floors.Search:
    return floors.search(
        frame(400, 4),
        frame(200, 5, "development"),
        seed=7,
        choices=(0.3, 3.0),
        workers=workers,
        heavy=1,
        log=lambda _: None,
    )


def test_the_search_learns_the_words_and_is_the_same_for_any_thread_count() -> None:
    one, three = search(1), search(3)
    strip = lambda rows: [{k: v for k, v in r.items() if k != "seconds"} for r in rows]  # noqa: E731
    assert strip(one.record["search"]) == strip(three.record["search"])
    assert one.record["chosen"] == three.record["chosen"]
    chosen = one.record["chosen"]
    assert set(chosen) == {t.name for t in floors.TASKS}
    assert chosen["band"]["dev"]["qwk"] > 0.9
    assert chosen["cwe"]["dev"]["macro_f1"] > 0.9
    assert all(entry["variant"] == one.record["representation"]["chosen"] for entry in chosen.values())
    assert chosen["band"]["dev_confusion"]["rows_truth_columns_predicted"] == list(sets.BANDS)
    band_rows = [r for r in one.record["search"] if r["task"] == "band"]
    assert len(band_rows) == 4  # two representations, two values of C
    assert all(len([r for r in one.record["search"] if r["task"] == t.name]) == 2 for t in floors.TASKS[1:])


def test_probabilities_and_the_reference() -> None:
    result = search(2)
    dev = frame(200, 5, "development")
    proba = floors.probabilities(result.features, result.models, dev)
    assert proba.height == dev.height
    band_columns = [f"band__{b}" for b in sets.BANDS]
    sums = proba.select(band_columns).to_numpy().sum(axis=1)
    assert np.allclose(sums, 1.0, atol=1e-5)
    ref = floors.reference(dev, proba)
    assert ref["with_filer_band"]["rows"] + ref["without_filer_band"]["rows"] == ref["all"]["rows"]
    # The filer band of the fixture is the true band wherever it is given.
    assert ref["with_filer_band"]["filer_qwk"] == pytest.approx(1.0)


def write_sets(folder: Path, root: Path) -> None:
    """A fixture sets folder with the record the script checks the files against."""
    folder.mkdir(parents=True)
    files: dict[str, Any] = {}
    for split, n, seed in (("train", 400, 4), ("development", 200, 5), ("test", 50, 6), ("shadow", 50, 8)):
        data = frame(n, seed, split)
        labels = data.select("cve_id", "split", "band", *(f"nvd_{m}" for m in METRIC_VALUES), "cwe")
        inputs = data.drop("band", "cwe", *(f"nvd_{m}" for m in METRIC_VALUES))
        for name, part in ((sets.inputs_name(split), inputs), (sets.labels_name(split), labels)):
            part.write_parquet(folder / name)
            files[name] = {"rows": part.height, "content_digest": sets.content_digest(folder / name)}
    (root / "results" / "models").mkdir(parents=True)
    (root / "results" / "parts").mkdir(parents=True)
    record = {
        "files": files,
        "lake_cut": "2026-11-13 06:00:00+00",
        "lake_release": "lake-test",
        "lake_content_digest": "x",
    }
    (root / "results" / "models" / "sets.json").write_text(json.dumps(record), encoding="utf-8")


def script_root(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "evaluation").mkdir(parents=True)
    (root / "evaluation" / "phase2_plan.yaml").write_text("defaults:\n  seed: 7\n", encoding="utf-8")
    registration = {"stages": [{"stage": "models", "hash": "abc123"}]}
    (root / "evaluation" / "registration.json").write_text(json.dumps(registration), encoding="utf-8")
    write_sets(root / "data" / "sets", root)
    return root


def test_the_script_writes_the_record_and_the_part(tmp_path: Path) -> None:
    root = script_root(tmp_path)
    assert train_floors.main(["--jobs", "2"], root=root) == 0
    record = json.loads((root / "results" / "models" / "floors.json").read_text(encoding="utf-8"))
    assert record["models_stage_hash"] == "abc123"
    assert set(record["sets"]) == set(train_floors.READ)
    assert record["predictions"]["test"]["rows"] == 50
    assert (root / "data" / "models" / "floors" / "floors.joblib").exists()
    part = json.loads((root / "results" / "parts" / "floors.json").read_text(encoding="utf-8"))
    assert "models.floors.band.dev" in part["values"]
    assert "models.floors.chosen" in part["tables"]


def test_the_script_refuses_sets_that_differ_from_the_record(tmp_path: Path) -> None:
    root = script_root(tmp_path)
    train = root / "data" / "sets" / sets.inputs_name("train")
    pl.read_parquet(train).head(10).write_parquet(train)
    with pytest.raises(SystemExit, match=r"differs from results/models/sets\.json"):
        train_floors.main(["--jobs", "1"], root=root)


def test_a_sample_run_leaves_the_committed_results_alone(tmp_path: Path) -> None:
    root = script_root(tmp_path)
    assert train_floors.main(["--sample", "100", "--jobs", "1"], root=root) == 0
    assert not (root / "results" / "models" / "floors.json").exists()
    assert (root / "data" / "models" / "floors-sample" / "floors.json").exists()


def test_the_floors_never_name_the_test_labels() -> None:
    root = Path(__file__).resolve().parents[2]
    files = [root / "scripts" / "train_floors.py", root / "packages/models/src/unscheduled_models/floors.py"]
    assert check_test_labels.check(root, files) == 2


def test_the_band_from_the_predicted_metrics() -> None:
    values = {
        "AV": ["N", "L"],
        "AC": ["L", "H"],
        "PR": ["N", "H"],
        "UI": ["N", "R"],
        "S": ["U", "C"],
        "C": ["H", "N"],
        "I": ["H", "N"],
        "A": ["H", "N"],
    }
    columns: dict[str, list[float]] = {"cve_id": ["CVE-1", "CVE-2"]}  # type: ignore[dict-item]
    for metric, (first, second) in values.items():
        columns[f"metric_{metric}__{first}"] = [0.9, 0.2]
        columns[f"metric_{metric}__{second}"] = [0.1, 0.8]
    rated = floors.band_from_metrics(pl.DataFrame(columns))
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H scores 9.8; no impact at all scores 0.0.
    assert rated == ["CRITICAL", "NONE"]
    assert floors.score("qwk", ["CRITICAL", "LOW", "HIGH"], ["CRITICAL", "NONE", "HIGH"]) < 1.0
