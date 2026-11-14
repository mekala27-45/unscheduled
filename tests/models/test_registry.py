"""The registry: versions numbered per model, chosen by the operating points or by development,
scored once test is, written to an MLflow store that opens from wherever it is unpacked."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path
from typing import Any

import pytest
import yaml
from unscheduled_models import registry

from scripts import build_registry

METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
ENV = {"github_run_id": "123", "github_sha": "a" * 40}


def fill_chosen(base: float) -> dict[str, Any]:
    chosen: dict[str, Any] = {
        "band": {"C": 1.0, "dev": {"qwk": base, "macro_f1": base - 0.1, "accuracy": base}},
        "cwe": {"C": 3.0, "dev": {"macro_f1": base - 0.3, "accuracy": base - 0.2, "top5_accuracy": base}},
    }
    for m in METRICS:
        chosen[f"metric_{m}"] = {"C": 0.3, "dev": {"kappa": base - 0.05, "macro_f1": base - 0.1}}
    return chosen


def records(root: Path) -> None:
    folder = root / "results" / "models"
    folder.mkdir(parents=True)
    common = {
        "sample": None,
        "sets": {"train_inputs.parquet": "b" * 64},
        "lake_release": "lake-20261112",
        "models_stage_hash": "c" * 64,
        "environment": ENV,
        "trained_at": "2026-11-14T05:00:00+00:00",
        "seconds": 60.0,
        "model_file": {"path": "data/models/x.joblib", "sha256": "d" * 64, "bytes": 10},
    }
    floors = {
        **common,
        "solver": "liblinear",
        "representation": {"chosen": "word"},
        "chosen": fill_chosen(0.6),
    }
    fallback = {
        **common,
        "primary": "joint",
        "embedding": {"id": "BAAI/bge-small-en-v1.5", "revision": "e" * 40},
        "designs": {
            "joint": {"width": 665, "chosen": fill_chosen(0.65)},
            "text": {"width": 384, "chosen": fill_chosen(0.5)},
        },
        "chosen": fill_chosen(0.65),
    }
    rank = {
        **common,
        "floor": {"C": 0.1, "class_weight": "balanced"},
        "lgbm": {"params": {"num_leaves": 31, "learning_rate": 0.05}, "trees": 200},
        "dev": {"floor": {"average_precision": 0.1}, "lgbm": {"average_precision": 0.2}},
    }
    survival = {
        **common,
        "cox": {"penalizer": 0.01, "step_size": 0.2},
        "forest": {"trees": 300, "min_samples_leaf": 100},
        "dev": {"cox": {"concordance": 0.70}, "forest": {"concordance": 0.75}},
    }
    product = {
        **common,
        "floor": {"threshold": 80, "vendor_neighbours": 3},
        "retrieval": {"pool": 300, "embedding": {"id": "BAAI/bge-small-en-v1.5", "revision": "e" * 40}},
        "dev": {
            "floor": {"cves": 10, "recall_at_10": 0.4},
            "floor_at_threshold": {"cves": 10, "recall_at_1": 0.3, "recall_at_10": 0.35},
            "retrieval": {"cves": 10, "recall_at_1": 0.2, "recall_at_10": 0.5},
        },
    }
    for name, record in {
        "floors": floors,
        "fallback": fallback,
        "rank": rank,
        "survival": survival,
        "product": product,
    }.items():
        (folder / f"{name}.json").write_text(json.dumps(record), encoding="utf-8")
    (folder / "sets.json").write_text(json.dumps({"lake_cut": "2026-11-13T06:00:00+00:00"}), encoding="utf-8")


def points(root: Path) -> None:
    (root / "config").mkdir(exist_ok=True)
    (root / "config" / "operating_points.yaml").write_text(
        yaml.safe_dump({"primary": {"fill": "fallback", "exploitation": "exploit_lgbm"}}), encoding="utf-8"
    )


def scoring(root: Path) -> None:
    per = {"qwk": 0.62, "macro_f1": 0.5, "rows": 100}
    fill = {"band": per, "cwe": {"macro_f1": 0.3}, **{f"metric_{m}": {"kappa": 0.5} for m in METRICS}}
    record = {
        "secondary": {
            "fill": {"fallback": fill, "fallback_text": fill, "floors": fill},
            "exploitation": {
                "exploit_lgbm": {"average_precision": 0.2},
                "exploit_floor": {"average_precision": 0.1},
            },
            "survival": {"cox": {"concordance": 0.7}, "forest": {"concordance": 0.72}},
            "product": {"floor_at_threshold": {"recall_at_10": 0.3}, "retrieval": {"recall_at_10": 0.45}},
        }
    }
    (root / "results" / "models" / "test_scoring.json").write_text(json.dumps(record), encoding="utf-8")


def by_model(versions: list[registry.Version]) -> dict[str, list[registry.Version]]:
    out: dict[str, list[registry.Version]] = {}
    for v in versions:
        out.setdefault(v.candidate.model, []).append(v)
    return out


def test_versions_are_numbered_and_development_chooses_survival_and_product(tmp_path: Path) -> None:
    records(tmp_path)
    versions, missing = registry.plan(tmp_path)
    assert missing == []
    models = by_model(versions)
    assert [v.candidate.role for v in models["unscheduled-band"]] == ["floor", "ablation", "model"]
    assert [v.version for v in models["unscheduled-band"]] == [1, 2, 3]
    assert models["unscheduled-metrics"][2].dev["mean_kappa"] == pytest.approx(0.6)
    # Before the operating points, only the models development chooses are chosen.
    assert not any(v.chosen for m in ("unscheduled-band", "unscheduled-exploit") for v in models[m])
    assert [v.chosen for v in models["unscheduled-survival"]] == [False, True]
    assert [v.chosen for v in models["unscheduled-product"]] == [False, True]
    assert {v.stage for v in versions} == {"candidate", "chosen"}


def test_the_operating_points_choose_and_the_scoring_scores(tmp_path: Path) -> None:
    records(tmp_path)
    points(tmp_path)
    models = by_model(registry.plan(tmp_path)[0])
    assert [v.stage for v in models["unscheduled-band"]] == ["candidate", "candidate", "chosen"]
    assert [v.stage for v in models["unscheduled-exploit"]] == ["candidate", "chosen"]
    scoring(tmp_path)
    models = by_model(registry.plan(tmp_path)[0])
    assert [v.stage for v in models["unscheduled-band"]] == ["scored", "scored", "scored"]
    assert models["unscheduled-band"][2].test == {"qwk": 0.62, "macro_f1": 0.5}


def test_a_missing_record_leaves_its_candidates_out_and_a_sample_is_refused(tmp_path: Path) -> None:
    records(tmp_path)
    (tmp_path / "results" / "models" / "product.json").unlink()
    versions, missing = registry.plan(tmp_path)
    assert missing == ["product"] and "unscheduled-product" not in by_model(versions)
    path = tmp_path / "results" / "models" / "rank.json"
    path.write_text(json.dumps({**json.loads(path.read_text()), "sample": 500}), encoding="utf-8")
    with pytest.raises(ValueError, match="sample run"):
        registry.plan(tmp_path)


def test_the_store_is_written_packed_and_checked(tmp_path: Path) -> None:
    records(tmp_path)
    points(tmp_path)
    scoring(tmp_path)
    (tmp_path / "results" / "parts").mkdir()
    assert build_registry.main(["--store", str(tmp_path / "data" / "store")], root=tmp_path) == 0
    export = json.loads((tmp_path / "results" / "registry" / "registry.json").read_text(encoding="utf-8"))
    names = [m["name"] for m in export["models"]]
    assert names == [
        "unscheduled-band",
        "unscheduled-metrics",
        "unscheduled-cwe",
        "unscheduled-exploit",
        "unscheduled-survival",
        "unscheduled-product",
    ]
    band = export["models"][0]
    assert band["aliases"] == {"chosen": 3, "scored": 3}
    assert band["versions"][2]["commit"] == "a" * 40 and band["versions"][2]["github_run_id"] == "123"
    archive = tmp_path / "results" / "registry" / export["archive"]["file"]
    assert archive.name.startswith("registry-") and export["archive"]["paths_made_relative"] > 0
    with tarfile.open(archive) as tar:
        names_in = tar.getnames()
        assert "store/mlflow.db" in names_in
        assert all(m.mtime == 0 for m in tar.getmembers())
    part = json.loads((tmp_path / "results" / "parts" / "registry.json").read_text(encoding="utf-8"))
    assert part["values"]["models.registry.versions"]["value"] == 15
    assert build_registry.main(["--check"], root=tmp_path) == 0
    path = tmp_path / "results" / "models" / "survival.json"
    changed = json.loads(path.read_text())
    changed["dev"]["cox"]["concordance"] = 0.9
    path.write_text(json.dumps(changed), encoding="utf-8")
    assert build_registry.main(["--check"], root=tmp_path) == 1
