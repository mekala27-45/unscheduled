"""The registry of Phase 2: MLflow runs written from the committed run records, the registered models
with their versions, stages and aliases, and the export the API and the console read.

The prompt names the Databricks workspace as the tracking server when DATABRICKS_HOST and
DATABRICKS_TOKEN exist and the probe passes. They do not (results/probe.json, phase2), so the store
is MLflow's SQLite backend, packed into one archive named by its digest for the release. Every run
comes from a record under results/models, and each record names its Actions run, its commit, the set
digests and its model file with its SHA-256, so the store is written from the repository alone: the
parameters and development metrics of every candidate, its test metrics once
results/models/test_scoring.json exists, and the record itself as the run's artifact.

A registered model's versions are its candidates: the floor and the model, and for the fill tasks
the text ablation. One version per registered model is chosen: the primary config/operating_points.yaml
freezes (the fill and exploitation models), or the one development prefers by the rule in CHOSEN_BY
(survival and product, which C1 and C2 do not judge). A version's stage tag is candidate, chosen once
it is chosen, and scored once the single test scoring has measured it, comparators included. The
alias chosen points at the chosen version, and the alias scored at the same version once it is
scored: that is the version the API serves.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import shutil
import tarfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from unscheduled_models.sets import METRICS

EXPERIMENT = "unscheduled-phase2"
STAGES = ("candidate", "chosen", "scored")
ROLES = ("model", "floor", "ablation")
CHOSEN_BY = {
    "unscheduled-survival": ("concordance", "the higher development concordance"),
    "unscheduled-product": ("recall_at_10", "the higher development recall at 10"),
}
DESCRIPTIONS = {
    "unscheduled-band": "The NVD CVSS 3.1 severity band of a CVE at day 0.",
    "unscheduled-metrics": "The eight NVD CVSS 3.1 base metrics of a CVE at day 0, one head each.",
    "unscheduled-cwe": "The NVD CWE of a CVE at day 0: the 50 most frequent in train, and other.",
    "unscheduled-exploit": "Whether KEV lists a CVE within 180 days of its publication, scored at day 0.",
    "unscheduled-survival": "The days from publication to a KEV listing, censored at the lake cut.",
    "unscheduled-product": "The CPE vendor and product pairs a CVE affects, as ranked candidates.",
}


@dataclass(frozen=True)
class Candidate:
    """One version of a registered model: where its record is, what it is, and how its numbers are
    read from the record and from the test scoring."""

    model: str
    record: str
    run_name: str
    role: str
    description: str
    params: Callable[[dict[str, Any]], dict[str, Any]]
    dev: Callable[[dict[str, Any]], dict[str, float]]
    test: Callable[[dict[str, Any]], dict[str, float]]
    primary_key: tuple[str, str] | None = None  # (operating point section, value) that makes it primary


@dataclass
class Version:
    candidate: Candidate
    version: int
    run_id: str = ""
    chosen: bool = False
    dev: dict[str, float] = field(default_factory=dict)
    test: dict[str, float] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)

    @property
    def stage(self) -> str:
        if self.test:
            return "scored"
        return "chosen" if self.chosen else "candidate"


def _numbers(prefix: str, values: dict[str, Any]) -> dict[str, float]:
    """The finite numbers of a flat result, named with a prefix; counts and text are left out."""
    out: dict[str, float] = {}
    for key, value in values.items():
        if isinstance(value, bool) or not isinstance(value, int | float):
            continue
        if key in {"rows", "cves", "positives", "clusters", "resamples"}:
            continue
        if math.isfinite(float(value)):
            out[f"{prefix}{key}"] = float(value)
    return out


def _fill_params(record: dict[str, Any], task: str, design: str | None) -> dict[str, Any]:
    chosen = record["designs"][design]["chosen"] if design else record["chosen"]
    if task == "metrics":
        out: dict[str, Any] = {f"C.{m}": chosen[f"metric_{m}"]["C"] for m in METRICS}
    else:
        out = {"C": chosen[task]["C"]}
    if design is None:
        out["representation"] = record["representation"]["chosen"]
        out["solver"] = record.get("solver")
    else:
        out["design"] = design
        out["width"] = record["designs"][design]["width"]
        out["embedding"] = f"{record['embedding']['id']}@{record['embedding']['revision']}"
    return out


def _fill_dev(record: dict[str, Any], task: str, design: str | None) -> dict[str, float]:
    chosen = record["designs"][design]["chosen"] if design else record["chosen"]
    if task == "metrics":
        kappas = {m: float(chosen[f"metric_{m}"]["dev"]["kappa"]) for m in METRICS}
        return {
            **{f"kappa.{m}": v for m, v in kappas.items()},
            "mean_kappa": sum(kappas.values()) / len(kappas),
        }
    return _numbers("", chosen[task]["dev"])


def _fill_test(scoring: dict[str, Any], task: str, model: str) -> dict[str, float]:
    per = scoring.get("secondary", {}).get("fill", {}).get(model)
    if not per:
        return {}
    if task == "metrics":
        kappas = {m: float(per[f"metric_{m}"]["kappa"]) for m in METRICS}
        return {
            **{f"kappa.{m}": v for m, v in kappas.items()},
            "mean_kappa": sum(kappas.values()) / len(kappas),
        }
    return _numbers("", per[task])


def _fill(task: str) -> Iterator[Candidate]:
    name = f"unscheduled-{task}"
    yield Candidate(
        name,
        "floors",
        f"{task} floor",
        "floor",
        "TF-IDF over the joined text beside the filer and CISA block, logistic regression",
        lambda r: _fill_params(r, task, None),
        lambda r: _fill_dev(r, task, None),
        lambda s: _fill_test(s, task, "floors"),
    )
    yield Candidate(
        name,
        "fallback",
        f"{task} text alone",
        "ablation",
        "frozen bge-small embeddings of the joined text alone, logistic regression",
        lambda r: _fill_params(r, task, "text"),
        lambda r: _fill_dev(r, task, "text"),
        lambda s: _fill_test(s, task, "fallback_text"),
    )
    yield Candidate(
        name,
        "fallback",
        f"{task} model",
        "model",
        "frozen bge-small embeddings beside the filer and CISA block, logistic regression",
        lambda r: _fill_params(r, task, "joint"),
        lambda r: _fill_dev(r, task, "joint"),
        lambda s: _fill_test(s, task, "fallback"),
        primary_key=("fill", "fallback"),
    )


def _exploit_test(scoring: dict[str, Any], name: str) -> dict[str, float]:
    per = scoring.get("secondary", {}).get("exploitation", {}).get(name)
    return _numbers("", per) if per else {}


def _survival_test(scoring: dict[str, Any], name: str) -> dict[str, float]:
    per = scoring.get("secondary", {}).get("survival", {}).get(name)
    return _numbers("", per) if per else {}


def _product_test(scoring: dict[str, Any], name: str) -> dict[str, float]:
    per = scoring.get("secondary", {}).get("product", {}).get(name)
    return _numbers("", per) if per else {}


def candidates() -> list[Candidate]:
    """Every version of every registered model, in the order the versions are numbered."""
    out: list[Candidate] = []
    for task in ("band", "metrics", "cwe"):
        out.extend(_fill(task))
    out.append(
        Candidate(
            "unscheduled-exploit",
            "rank",
            "exploitation floor",
            "floor",
            "logistic regression on the day 0 features and the band floor's projection, balanced",
            lambda r: {"C": r["floor"]["C"], "class_weight": r["floor"]["class_weight"]},
            lambda r: _numbers("", r["dev"]["floor"]),
            lambda s: _exploit_test(s, "exploit_floor"),
        )
    )
    out.append(
        Candidate(
            "unscheduled-exploit",
            "rank",
            "exploitation model",
            "model",
            "LightGBM on the same features, tuned by Optuna on time ordered folds",
            lambda r: {
                **{f"lgbm.{k}": v for k, v in r["lgbm"]["params"].items()},
                "trees": r["lgbm"]["trees"],
            },
            lambda r: _numbers("", r["dev"]["lgbm"]),
            lambda s: _exploit_test(s, "exploit_lgbm"),
            primary_key=("exploitation", "exploit_lgbm"),
        )
    )
    out.append(
        Candidate(
            "unscheduled-survival",
            "survival",
            "survival Cox",
            "floor",
            "lifelines Cox proportional hazards on the day 0 features without the text",
            lambda r: {"penalizer": r["cox"]["penalizer"], "step_size": r["cox"]["step_size"]},
            lambda r: _numbers("", r["dev"]["cox"]),
            lambda s: _survival_test(s, "cox"),
        )
    )
    out.append(
        Candidate(
            "unscheduled-survival",
            "survival",
            "survival forest",
            "model",
            "scikit-survival random survival forest on the same design",
            lambda r: {"trees": r["forest"]["trees"], "min_samples_leaf": r["forest"]["min_samples_leaf"]},
            lambda r: _numbers("", r["dev"]["forest"]),
            lambda s: _survival_test(s, "forest"),
        )
    )
    out.append(
        Candidate(
            "unscheduled-product",
            "product",
            "product floor",
            "floor",
            "normalized vendor and product strings, an exact match, then a token set ratio",
            lambda r: {
                "threshold": r["floor"]["threshold"],
                "vendor_neighbours": r["floor"]["vendor_neighbours"],
            },
            lambda r: _numbers("", r["dev"]["floor_at_threshold"]),
            lambda s: _product_test(s, "floor_at_threshold"),
        )
    )
    out.append(
        Candidate(
            "unscheduled-product",
            "product",
            "product retrieval",
            "model",
            "cosine between bge-small embeddings of the joined text and of every CPE vendor and product",
            lambda r: {
                "pool": r["retrieval"]["pool"],
                "embedding": f"{r['retrieval']['embedding']['id']}@{r['retrieval']['embedding']['revision']}",
            },
            lambda r: _numbers("", r["dev"]["retrieval"]),
            lambda s: _product_test(s, "retrieval"),
        )
    )
    return out


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _millis(stamp: str) -> int:
    return int(datetime.fromisoformat(stamp).timestamp() * 1000)


def _param(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return text[:6000]


def plan(root: Path) -> tuple[list[Version], list[str]]:
    """The versions the committed records allow, numbered per registered model, with their stage;
    and the records not committed yet, which leave their candidates out."""
    results = root / "results" / "models"
    records: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    for candidate in candidates():
        if candidate.record in records or candidate.record in missing:
            continue
        path = results / f"{candidate.record}.json"
        if path.exists():
            record = json.loads(path.read_text(encoding="utf-8"))
            if record.get("sample"):
                raise ValueError(f"{path} is a sample run; the registry takes full runs only")
            records[candidate.record] = record
        else:
            missing.append(candidate.record)
    points_path = root / "config" / "operating_points.yaml"
    points = yaml.safe_load(points_path.read_text(encoding="utf-8")) if points_path.exists() else None
    scoring_path = results / "test_scoring.json"
    scoring = json.loads(scoring_path.read_text(encoding="utf-8")) if scoring_path.exists() else None
    versions: list[Version] = []
    numbers: dict[str, int] = {}
    for candidate in candidates():
        record = records.get(candidate.record)
        if record is None:
            continue
        numbers[candidate.model] = numbers.get(candidate.model, 0) + 1
        v = Version(candidate, numbers[candidate.model])
        v.params = candidate.params(record)
        v.dev = candidate.dev(record)
        if scoring is not None:
            v.test = candidate.test(scoring)
        versions.append(v)
    for model, (metric, _rule) in CHOSEN_BY.items():
        mine = [v for v in versions if v.candidate.model == model]
        if len(mine) == 2 and all(metric in v.dev for v in mine):
            # The higher development value; a tie goes to the floor, the earlier version.
            max(mine, key=lambda v: (v.dev[metric], -v.version)).chosen = True
    if points is not None:
        primary = points.get("primary", {})
        for v in versions:
            key = v.candidate.primary_key
            if key is not None and primary.get(key[0]) == key[1]:
                v.chosen = True
    return versions, missing


def build(root: Path, store: Path) -> dict[str, Any]:
    """Write the store from the committed records and return the export of what it holds."""
    # No usage reports leave the build, and no hints for coding agents in its log.
    os.environ.setdefault("MLFLOW_DISABLE_TELEMETRY", "true")
    os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")
    import mlflow
    from mlflow.entities import Metric, Param, RunTag
    from mlflow.tracking import MlflowClient

    versions, missing = plan(root)
    if store.exists():
        shutil.rmtree(store)
    store.mkdir(parents=True)
    uri = f"sqlite:///{(store / 'mlflow.db').as_posix()}"
    client = MlflowClient(tracking_uri=uri, registry_uri=uri)
    experiment_id = client.create_experiment(EXPERIMENT, artifact_location=(store / "artifacts").as_uri())
    results = root / "results" / "models"
    records: dict[str, dict[str, Any]] = {}
    for v in versions:
        name = v.candidate.record
        if name not in records:
            records[name] = json.loads((results / f"{name}.json").read_text(encoding="utf-8"))
        record = records[name]
        env = record.get("environment", {})
        end = _millis(record["trained_at"])
        start = end - int(float(record.get("seconds", 0)) * 1000)
        tags = {
            "mlflow.runName": v.candidate.run_name,
            "mlflow.source.git.commit": str(env.get("github_sha") or ""),
            "mlflow.source.name": f"scripts/train_{'rank' if name == 'rank' else name}.py",
            "github_run_id": str(env.get("github_run_id") or ""),
            "record": f"results/models/{name}.json",
            "record_sha256": file_sha256(results / f"{name}.json"),
            "lake_release": str(record.get("lake_release") or ""),
            "models_stage_hash": str(record.get("models_stage_hash") or ""),
            "role": v.candidate.role,
            "registered_model": v.candidate.model,
        }
        for set_name, digest in sorted(record.get("sets", {}).items()):
            tags[f"set.{set_name}"] = str(digest)
        model_file = record.get("model_file", {})
        if model_file:
            tags["model_file"] = str(model_file.get("path", ""))
            tags["model_file_sha256"] = str(model_file.get("sha256", ""))
        run = client.create_run(experiment_id, start_time=start, tags=tags, run_name=v.candidate.run_name)
        v.run_id = run.info.run_id
        metrics = [Metric(f"dev.{k}", val, end, 0) for k, val in sorted(v.dev.items())]
        metrics += [Metric(f"test.{k}", val, end, 0) for k, val in sorted(v.test.items())]
        params = [Param(k, _param(val)) for k, val in sorted(v.params.items())]
        client.log_batch(
            v.run_id,
            metrics=metrics,
            params=params,
            tags=[RunTag("stage", v.stage), RunTag("chosen", str(v.chosen).lower())],
        )
        client.log_dict(v.run_id, record, f"record/{name}.json")
        client.log_dict(
            v.run_id,
            {
                "registered_model": v.candidate.model,
                "role": v.candidate.role,
                "description": v.candidate.description,
                "model_file": model_file,
                "predictions": record.get("predictions"),
            },
            "model/descriptor.json",
        )
        client.set_terminated(v.run_id, "FINISHED", end_time=end)
    models: dict[str, dict[str, Any]] = {}
    for v in versions:
        model = v.candidate.model
        if model not in models:
            client.create_registered_model(model, description=DESCRIPTIONS[model])
            models[model] = {"name": model, "description": DESCRIPTIONS[model], "versions": [], "aliases": {}}
        run = client.get_run(v.run_id)
        created = client.create_model_version(
            model,
            source=f"{run.info.artifact_uri}/model",
            run_id=v.run_id,
            tags={"role": v.candidate.role, "stage": v.stage, "chosen": str(v.chosen).lower()},
            description=v.candidate.description,
        )
        if int(created.version) != v.version:
            raise RuntimeError(f"{model} numbered version {created.version}, expected {v.version}")
        if v.chosen:
            client.set_registered_model_alias(model, "chosen", str(v.version))
            models[model]["aliases"]["chosen"] = v.version
            if v.test:
                client.set_registered_model_alias(model, "scored", str(v.version))
                models[model]["aliases"]["scored"] = v.version
        models[model]["versions"].append(
            {
                "version": v.version,
                "run_id": v.run_id,
                "run_name": v.candidate.run_name,
                "role": v.candidate.role,
                "stage": v.stage,
                "chosen": v.chosen,
                "description": v.candidate.description,
                "params": v.params,
                "dev": v.dev,
                "test": v.test,
                "record": f"results/models/{v.candidate.record}.json",
                "commit": run.data.tags.get("mlflow.source.git.commit"),
                "github_run_id": run.data.tags.get("github_run_id"),
                "model_file_sha256": run.data.tags.get("model_file_sha256"),
            }
        )
    for model, (_metric, rule) in CHOSEN_BY.items():
        if model in models:
            models[model]["chosen_by"] = rule
    for model in models:
        if model not in CHOSEN_BY:
            models[model]["chosen_by"] = "config/operating_points.yaml, primary"
    return {
        "tracking": {
            "backend": "MLflow SQLite store, packed by digest (the Databricks pair is not set)",
            "mlflow": mlflow.__version__,
            "experiment": EXPERIMENT,
        },
        "records_missing": missing,
        "models": list(models.values()),
    }


def pack(store: Path, out: Path) -> tuple[Path, str]:
    """The store as one gzipped tar with fixed times and owners, named by its SHA-256."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", compresslevel=9) as tar:
        for path in sorted(store.rglob("*")):
            info = tar.gettarinfo(str(path), arcname=path.relative_to(store.parent).as_posix())
            info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
            if path.is_file():
                with path.open("rb") as handle:
                    tar.addfile(info, handle)
            else:
                tar.addfile(info)
    data = buffer.getvalue()
    digest = hashlib.sha256(data).hexdigest()
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("registry-*.tar.gz"):
        old.unlink()
    target = out / f"registry-{digest[:12]}.tar.gz"
    target.write_bytes(data)
    return target, digest


def relocate(store: Path) -> int:
    """Rewrite the store's absolute artifact paths to paths relative to the store's folder, so the
    unpacked archive opens with `mlflow ui --backend-store-uri sqlite:///mlflow.db` from wherever it
    lands. Returns the number of values rewritten."""
    import sqlite3

    prefixes = (store.resolve().as_uri(), str(store.resolve()))
    changed = 0
    with sqlite3.connect(store / "mlflow.db") as con:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        for table in tables:
            columns = [
                r[1]
                for r in con.execute(f'PRAGMA table_info("{table}")')
                if "CHAR" in r[2].upper() or "TEXT" in r[2].upper()
            ]
            for column in columns:
                for prefix in prefixes:
                    cur = con.execute(
                        f'UPDATE "{table}" SET "{column}" = REPLACE("{column}", ?, \'.\') WHERE "{column}" LIKE ?',
                        (prefix, prefix + "%"),
                    )
                    changed += cur.rowcount
    with sqlite3.connect(store / "mlflow.db") as con:
        con.execute("VACUUM")
    return changed
