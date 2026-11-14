"""The predictions: loaded by the sync from an optional bundle file, served in the CVE record with
their models and uncertainty, filtered on in the list, emptied by a bundle that carries none; and
POST /v1/predict scoring a description through the ONNX floor and LightGBM, under the budget."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import lightgbm as lgb
import numpy as np
import pytest
from fastapi.testclient import TestClient
from unscheduled_api import scoring
from unscheduled_api.app import create_app
from unscheduled_api.schemas import PredictRequest
from unscheduled_models import export, floors, rank
from unscheduled_models.features import Features

from tests.api.conftest import PUBLISHED_AT, TAG, sync_until_done
from tests.api.fixtures.bundle import write_bundle
from tests.api.fixtures.github import FakeGitHub
from tests.models.test_floors import frame
from tests.models.test_rank import rank_frame

METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def prediction(cve_id: str, band: str = "HIGH") -> dict[str, Any]:
    row: dict[str, Any] = {
        "cve_id": cve_id,
        "band": band,
        "band_p_low": 0.05,
        "band_p_medium": 0.15,
        "band_p_high": 0.6 if band == "HIGH" else 0.1,
        "band_p_critical": 0.2 if band == "HIGH" else 0.7,
        "band_set": f"{band}|CRITICAL" if band == "HIGH" else band,
        "cwe": "CWE-79",
        "cwe_p": 0.4,
        "cwe_top": "CWE-79|CWE-89|CWE-20|CWE-22|other",
        "exploit_score": 0.03,
        "exploit_p": 0.011,
        "exploit_pct": 97.5,
        "listed_by_30": 0.002,
        "listed_by_90": 0.004,
        "listed_by_180": 0.006,
        "products": "acme:door|acme:gate",
    }
    for m, v in zip(METRICS, ("N", "L", "N", "N", "U", "H", "H", "H"), strict=True):
        row[f"metric_{m}"] = v
        row[f"metric_{m}_p"] = 0.8
        row[f"metric_{m}_set"] = v if m != "PR" else "N|L"
    return row


MODELS = {
    "batch": "abc123def456",
    "made_on": "2026-11-14",
    "rule": "development, test and shadow window CVEs",
    "models": [
        {
            "name": name,
            "description": name,
            "aliases": {"chosen": chosen},
            "versions": [{"version": v, "role": "floor" if v == 1 else "model"} for v in range(1, 4)],
        }
        for name, chosen in (
            ("unscheduled-band", 3),
            ("unscheduled-metrics", 3),
            ("unscheduled-cwe", 3),
            ("unscheduled-exploit", 2),
            ("unscheduled-survival", 1),
            ("unscheduled-product", 2),
        )
    ],
}


@pytest.fixture
def predicted(client: TestClient, github: FakeGitHub, tmp_path: Path) -> TestClient:
    folder = tmp_path / "with-predictions"
    write_bundle(
        folder,
        predictions=[prediction("CVE-2026-90003"), prediction("CVE-2025-90004", "CRITICAL")],
        models_value=MODELS,
    )
    github.publish(folder, TAG, PUBLISHED_AT)
    answers = sync_until_done(client)
    assert answers[-1]["status"] == "done"
    return client


def test_the_record_carries_each_prediction_with_its_model_and_uncertainty(predicted: TestClient) -> None:
    body = predicted.get("/v1/cves/CVE-2026-90003").json()
    block = body["predictions"]
    assert (
        block["batch"] == "abc123def456"
        and block["window"] == "shadow"
        and "never NVD values" in block["note"]
    )
    values = {v["field"]: v for v in block["values"]}
    assert values["band"]["value"] == "HIGH" and values["band"]["set"] == ["HIGH", "CRITICAL"]
    assert values["band"]["model"] == "unscheduled-band" and values["band"]["version"] == 3
    assert values["band"]["probabilities"]["HIGH"] == pytest.approx(0.6)
    assert values["metric_PR"]["set"] == ["N", "L"] and values["metric_AV"]["value"] == "N"
    assert values["exploitation"]["detail"]["percentile"] == pytest.approx(97.5)
    assert "EPSS" in values["exploitation"]["detail"]["epss"]["note"]
    assert values["kev_listing"]["value"] == {"30": 0.002, "90": 0.004, "180": 0.006}
    assert values["products"]["value"] == ["acme:door", "acme:gate"]
    assert (
        values["kev_listing"]["model"] == "unscheduled-survival" and values["kev_listing"]["role"] == "floor"
    )


def test_a_cve_without_a_prediction_says_why(predicted: TestClient) -> None:
    train = predicted.get("/v1/cves/CVE-2021-90001").json()
    assert train["predictions"] is None and "fit on CVEs published before 2024" in train["predictions_note"]
    later = predicted.get("/v1/cves/CVE-2026-90005").json()
    assert later["predictions"] is None and "2026-11-14" in later["predictions_note"]


def test_the_list_shows_and_filters_the_predicted_band(predicted: TestClient) -> None:
    page = predicted.get("/v1/cves").json()
    bands = {i["cve_id"]: i["predicted_band"] for i in page["items"]}
    assert bands["CVE-2026-90003"] == "HIGH" and bands["CVE-2025-90004"] == "CRITICAL"
    assert bands["CVE-2021-90001"] is None
    critical = predicted.get("/v1/cves?predicted_band=CRITICAL").json()
    assert [i["cve_id"] for i in critical["items"]] == ["CVE-2025-90004"]
    assert predicted.get("/v1/cves?predicted_band=SEVERE").status_code == 422


def test_a_bundle_without_predictions_empties_them(
    predicted: TestClient, github: FakeGitHub, tmp_path: Path, clock: Any
) -> None:
    plain = tmp_path / "plain"
    write_bundle(plain, generated_at="2026-11-08T05:00:00Z")
    github.publish(plain, "serving-202611080500", "2026-11-08T05:10:00Z")
    clock.advance(120)
    answers = sync_until_done(predicted)
    assert answers[-1]["status"] == "done"
    body = predicted.get("/v1/cves/CVE-2026-90003").json()
    assert (
        body["predictions"] is None and body["predictions_note"] == "the loaded bundle carries no predictions"
    )


# POST /v1/predict --------------------------------------------------------------------------------


def serving_folder(root: Path) -> None:
    """Small real models exported the way scripts/export_onnx.py exports the real ones."""
    folder = root / "models" / "serving"
    folder.mkdir(parents=True)
    train = frame(500, 3)
    features = Features("word")
    x = features.fit_transform(train)
    rows = floors.labelled(train, "band")
    model, _ = floors.fit(x[rows], floors.labels_at(train, "band", rows), 1.0, 7)
    classes = [str(c) for c in model.classes_]
    assert classes == ["CRITICAL", "HIGH", "LOW", "MEDIUM"] or set(classes) == {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }
    order = [classes.index(b) for b in ("LOW", "MEDIUM", "HIGH", "CRITICAL")]
    ests = [model.estimators_[i] for i in order]
    spec = export.floor_spec(features)
    graph = export.linear_onnx(ests, ["LOW", "MEDIUM", "HIGH", "CRITICAL"], spec["width"], "band_floor")
    (folder / "band_floor.onnx").write_bytes(graph.SerializeToString())
    (folder / "band_floor.json.gz").write_bytes(gzip.compress(json.dumps(spec).encode()))
    ranked = rank_frame(1500, 4, datetime(2021, 5, 7, tzinfo=UTC), 900)
    ranked = rank.with_projection(ranked, np.random.default_rng(1).dirichlet(np.ones(4), ranked.height))
    design = rank.DayZero().fit(ranked)
    dense = design.dense(ranked)
    booster = lgb.train(
        {"objective": "binary", "num_leaves": 7, "verbose": -1, "deterministic": True, "seed": 1},
        lgb.Dataset(dense, rank.truth(ranked), categorical_feature=design.categorical_indices()),
        num_boost_round=20,
    )
    (folder / "exploit_lgbm.onnx").write_bytes(export.lgbm_onnx(booster, dense.shape[1]).SerializeToString())
    (folder / "exploit_day0.json").write_text(json.dumps(export.day0_spec(design)), encoding="utf-8")
    serving = {
        "batch": "abc123def456",
        "made_on": "2026-11-14",
        "band_floor": {
            "model": "unscheduled-band",
            "version": 1,
            "role": "floor",
            "temperature": 1.3,
            "conformal_cutoff": 0.8,
        },
        "exploit": {
            "model": "unscheduled-exploit",
            "version": 2,
            "role": "model",
            "isotonic": {"x": [0.0, 0.5, 1.0], "y": [0.0, 0.2, 0.6]},
            "quantiles": list(np.linspace(0, 1, 1001)),
        },
    }
    (folder / "serving.json").write_text(json.dumps(serving), encoding="utf-8")


def test_predict_scores_a_description_under_the_budget(make_services: Any, tmp_path: Path) -> None:
    root = tmp_path / "root"
    serving_folder(root)
    services = make_services()
    services.scorer = scoring.Scorer(root)
    client = TestClient(create_app(services))
    body = {
        "description": "remote code execution without authentication in the admin page of the door",
        "filer": "acme",
        "cvss31_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwes": ["CWE-94"],
        "vendor": "acme",
        "product": "door",
    }
    response = client.post("/v1/predict", json=body)
    assert response.status_code == 200, response.text
    answer = response.json()
    values = {v["field"]: v for v in answer["values"]}
    band = values["band"]
    assert band["value"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} and band["value"] in band["set"]
    assert sum(band["probabilities"].values()) == pytest.approx(1.0, abs=1e-5)
    assert band["model"] == "unscheduled-band" and band["role"] == "floor"
    assert 0.0 <= values["exploitation"]["value"] <= 0.6
    assert 0.0 <= values["exploitation"]["detail"]["percentile"] <= 100.0
    assert "never NVD values" in answer["note"]
    assert response.headers["X-Budget-Remaining"].isdigit()
    # The same text twice gives the same answer; a short description is refused.
    again = client.post("/v1/predict", json=body).json()
    assert again["values"] == answer["values"]
    assert client.post("/v1/predict", json={"description": "too short"}).status_code == 422
    big = {"description": "x" * 3999, "filer": "y" * 120, "vendor": "z" * 120, "product": "w" * 120}
    assert (
        client.post(
            "/v1/predict",
            content=json.dumps(big).encode() + b" " * 20000,
            headers={"content-type": "application/json"},
        ).status_code
        == 413
    )


def test_the_request_row_reads_the_vector_as_the_sets_do() -> None:
    body = PredictRequest(
        description="a buffer overflow in the parser of the door controller firmware",
        cvss31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        vendor="acme",
    )
    row = scoring.request_row(body, datetime(2026, 11, 14, tzinfo=UTC))
    assert row["filer_band"] == "CRITICAL" and row["filer_AV"] == "N" and row["filer_A"] == "H"
    assert row["published_month"] == 2026 * 12 + 11 and row["affected_entries"] == 1
    assert row["text"].endswith("Filer score: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert scoring.aps_set([0.1, 0.2, 0.6, 0.1], 0.7, ("LOW", "MEDIUM", "HIGH", "CRITICAL")) == [
        "MEDIUM",
        "HIGH",
    ]


def test_without_the_models_predict_says_so(make_services: Any, tmp_path: Path) -> None:
    services = make_services()
    services.scorer = scoring.Scorer(tmp_path / "empty")
    client = TestClient(create_app(services))
    body = {"description": "remote code execution without authentication in the admin page"}
    response = client.post("/v1/predict", json=body)
    assert response.status_code == 503 and "not in this deployment" in response.json()["detail"]
