"""Request time scoring for POST /v1/predict: the band floor and the exploitation model in ONNX.

A submitted description, with what a filer gives at publication, is scored as a CVE at its day 0:
the joined text and the filer values become the band floor's input row (unscheduled_core.featurize,
from the spec scripts/export_onnx.py checked against scikit-learn), the floor gives the four band
probabilities, and those probabilities with the day 0 values become LightGBM's row. The served band
probabilities are scaled by the floor's development temperature and carry its 90 percent conformal
set; the exploitation score goes through the isotonic map fit on development and is placed among
the batch's scores. ModernBERT and its fallback are served from the batch predictions only
(docs/adr/0008). The files are read once per process, on the first request that needs them.
"""

from __future__ import annotations

import gzip
import json
import math
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from unscheduled_core.featurize import (
    DayZeroRow,
    FloorFeatures,
    cvss31_metrics,
    cvss31_score,
    joined_text,
    severity,
)

from unscheduled_api.bundle import BANDS
from unscheduled_api.problems import ProblemError
from unscheduled_api.schemas import PredictedValue, PredictRequest

FOLDER = Path("models") / "serving"
FILES = ("band_floor.onnx", "band_floor.json.gz", "exploit_lgbm.onnx", "exploit_day0.json", "serving.json")
NOTE = (
    "Predictions of the Phase 2 floor and exploitation models for the text sent, scored as a CVE on "
    "the day it is published; never NVD values. The band probabilities are calibrated on development "
    "and the set holds the true band nine times in ten on development."
)


def softmax_scaled(probabilities: list[float], temperature: float) -> list[float]:
    logits = [math.log(max(p, 1e-12)) / temperature for p in probabilities]
    top = max(logits)
    exps = [math.exp(z - top) for z in logits]
    total = sum(exps)
    return [e / total for e in exps]


def aps_set(probabilities: list[float], cutoff: float, classes: tuple[str, ...]) -> list[str]:
    """The adaptive set: classes most probable first until their mass reaches the cutoff, the class
    that crosses it included, as unscheduled_models.conformal builds it."""
    order = sorted(range(len(probabilities)), key=lambda i: (-probabilities[i], i))
    kept: list[str] = []
    before = 0.0
    for i in order:
        if kept and before >= cutoff:
            break
        kept.append(classes[i])
        before += probabilities[i]
    return [c for c in classes if c in kept]


def isotonic(x: list[float], y: list[float], value: float) -> float:
    """The isotonic map as numpy.interp reads it, clipped at both ends."""
    if value <= x[0]:
        return y[0]
    if value >= x[-1]:
        return y[-1]
    lo, hi = 0, len(x) - 1
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if x[mid] <= value:
            lo = mid
        else:
            hi = mid
    span = x[hi] - x[lo]
    return y[lo] if span == 0 else y[lo] + (y[hi] - y[lo]) * (value - x[lo]) / span


def percentile(quantiles: list[float], value: float) -> float:
    """Where a score falls among the batch, from its 1,001 quantiles, as a percent."""
    below = sum(1 for q in quantiles if q <= value)
    return round(100.0 * max(below - 1, 0) / (len(quantiles) - 1), 1)


def request_row(body: PredictRequest, now: datetime) -> dict[str, Any]:
    """The request as a set row: the names the training sets give these values at day 0."""
    products = " ".join(p for p in (body.vendor, body.product) if p).strip() or None
    metrics = cvss31_metrics(body.cvss31_vector)
    band = severity(cvss31_score(metrics)) if metrics else None
    row: dict[str, Any] = {
        "text": joined_text(body.description, body.filer, products, body.cvss31_vector),
        "filer": body.filer,
        "filer_type": body.filer_type,
        "filer_cvss31_vector": body.cvss31_vector,
        "filer_band": band if band in BANDS else None,
        "filer_cwes": list(body.cwes),
        "published_year": now.year,
        "published_month": now.year * 12 + now.month,
        "reserved_to_published_days": body.reserved_days,
        "affected_entries": 1 if products else 0,
        "vendor_present": bool(body.vendor),
        "product_present": bool(body.product),
        "versions_present": False,
        "exploit_code_by_day0": body.exploit_code,
    }
    for name, value in metrics.items():
        row[f"filer_{name}"] = value
    return row


class Scorer:
    def __init__(self, root: Path) -> None:
        self.folder = root / FOLDER
        self._lock = threading.Lock()
        self._loaded: dict[str, Any] | None = None

    def available(self) -> bool:
        return all((self.folder / name).exists() for name in FILES)

    def _load(self) -> dict[str, Any]:
        with self._lock:
            if self._loaded is None:
                if not self.available():
                    raise ProblemError(
                        "data-not-loaded", "the prediction models are not in this deployment yet"
                    )
                import numpy as np
                import onnxruntime as ort

                options = ort.SessionOptions()
                options.intra_op_num_threads = 1
                options.log_severity_level = 3

                def session(name: str) -> Any:
                    return ort.InferenceSession(
                        str(self.folder / name), options, providers=["CPUExecutionProvider"]
                    )

                spec = json.loads(gzip.decompress((self.folder / "band_floor.json.gz").read_bytes()))
                self._loaded = {
                    "np": np,
                    "floor": session("band_floor.onnx"),
                    "lgbm": session("exploit_lgbm.onnx"),
                    "features": FloorFeatures(spec),
                    "day0": DayZeroRow(json.loads((self.folder / "exploit_day0.json").read_text("utf-8"))),
                    "serving": json.loads((self.folder / "serving.json").read_text("utf-8")),
                }
            return self._loaded

    def score(self, body: PredictRequest, now: datetime) -> list[PredictedValue]:
        loaded = self._load()
        np = loaded["np"]
        row = request_row(body, now)
        features: FloorFeatures = loaded["features"]
        x = np.zeros((1, features.width), dtype=np.float32)
        for j, v in features.transform(row).items():
            x[0, j] = v
        raw = [float(p) for p in loaded["floor"].run(None, {"features": x})[0][0]]
        serving = loaded["serving"]
        floor = serving["band_floor"]
        scaled = softmax_scaled(raw, float(floor["temperature"]))
        best = max(range(len(BANDS)), key=lambda i: (scaled[i], -i))
        day0: DayZeroRow = loaded["day0"]
        x2 = np.asarray([day0.transform(row, raw)], dtype=np.float32)
        score = float(loaded["lgbm"].run(None, {"features": x2})[1][0][1])
        exploit = serving["exploit"]
        probability = isotonic(exploit["isotonic"]["x"], exploit["isotonic"]["y"], score)
        return [
            PredictedValue(
                field="band",
                model=floor["model"],
                version=floor["version"],
                role=floor["role"],
                value=BANDS[best],
                probability=round(scaled[best], 6),
                probabilities={b: round(p, 6) for b, p in zip(BANDS, scaled, strict=True)},
                set=aps_set(scaled, float(floor["conformal_cutoff"]), BANDS),
            ),
            PredictedValue(
                field="exploitation",
                model=exploit["model"],
                version=exploit["version"],
                role=exploit["role"],
                value=round(probability, 6),
                probability=round(probability, 6),
                detail={
                    "meaning": "the chance KEV lists this CVE within 180 days of publication, scored at day 0",
                    "score": round(score, 6),
                    "percentile": percentile(exploit["quantiles"], score),
                    "percentile_of": f"every CVE in batch {serving['batch']}",
                },
            ),
        ]
