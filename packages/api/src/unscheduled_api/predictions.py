"""The predictions block of a CVE: the Phase 2 batch predictions read from the prediction table, each
labeled with the registered model and version that made it, from the registry export the loaded
bundle carried (models.json, kept in the settings table under models).

A prediction is never an NVD value. Every block says so, gives the probability calibrated on
development and the 90 percent conformal set, and puts EPSS beside the exploitation score with the
reason the two are not alike: EPSS is read on the day it was published, the model at day 0.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

import sqlalchemy as sa
from pydantic import JsonValue

from unscheduled_api import db
from unscheduled_api.bundle import BANDS, METRICS
from unscheduled_api.schemas import PredictedValue, Predictions

NOTE = (
    "Predictions of the Phase 2 models, never NVD values. Each names its registered model and version. "
    "A probability is calibrated on the development window, and a set holds the true value nine times "
    "in ten on development; coverage on later CVEs is measured, not promised."
)
EPSS_NOTE = (
    "EPSS from FIRST, beside the model and not compared with it here: EPSS is read on the day it was "
    "published, after the CVE had days of exposure, while the model scores at day 0."
)
FIELD_MODELS = {
    "band": "unscheduled-band",
    "metrics": "unscheduled-metrics",
    "cwe": "unscheduled-cwe",
    "exploitation": "unscheduled-exploit",
    "kev_listing": "unscheduled-survival",
    "products": "unscheduled-product",
}
WINDOWS = (
    ("development", date(2024, 1, 1), date(2024, 12, 31)),
    ("test", date(2025, 1, 1), date(2026, 3, 31)),
    ("gap", date(2026, 4, 1), date(2026, 4, 14)),
    ("shadow", date(2026, 4, 15), date(9999, 12, 31)),
)


def window_of(published: datetime | None) -> str | None:
    """The config/splits.yaml window a CVE was published in, from 2024 on; earlier CVEs are train."""
    if published is None:
        return None
    day = published.date()
    for name, start, end in WINDOWS:
        if start <= day <= end:
            return name
    return "train" if day < WINDOWS[0][1] else None


def chosen(models: dict[str, Any] | None, field: str) -> tuple[int | None, str | None]:
    """The chosen version of the field's registered model and its role, from the export."""
    if not models:
        return None, None
    name = FIELD_MODELS[field]
    for model in models.get("models") or []:
        if model.get("name") == name:
            version = (model.get("aliases") or {}).get("chosen")
            role = next(
                (v.get("role") for v in model.get("versions") or [] if v.get("version") == version), None
            )
            return (int(version) if version is not None else None), role
    return None, None


def missing_reason(models: dict[str, Any] | None, published: datetime | None) -> str:
    if not models:
        return "the loaded bundle carries no predictions"
    window = window_of(published)
    if window == "train":
        return "the models were fit on CVEs published before 2024, so this one carries no prediction"
    if window == "gap":
        return "the gap window between test and shadow is used by no model, so this CVE carries no prediction"
    batch = models.get("made_on")
    return (
        f"this CVE is not in the batch of predictions made on {batch}"
        if batch
        else "this CVE is not in the batch"
    )


def _value(
    field: str,
    models: dict[str, Any] | None,
    value: JsonValue,
    probability: float | None = None,
    probabilities: dict[str, float] | None = None,
    members: list[str] | None = None,
    detail: dict[str, JsonValue] | None = None,
) -> PredictedValue:
    version, role = chosen(models, field)
    return PredictedValue(
        field=field,
        model=FIELD_MODELS[field],
        version=version,
        role=role,
        value=value,
        probability=None if probability is None else round(float(probability), 6),
        probabilities=probabilities,
        set=members,
        detail=detail,
    )


def block(
    conn: sa.Connection, cve_id: str, models: dict[str, Any] | None, cve_row: dict[str, Any]
) -> tuple[Predictions | None, str | None]:
    """The CVE's predictions, or none with the reason."""
    row = conn.execute(sa.select(db.prediction).where(db.prediction.c.cve_id == cve_id)).mappings().first()
    if row is None or not models:
        return None, missing_reason(models, cve_row.get("published"))
    values: list[PredictedValue] = []
    probabilities = {b: round(float(row[f"band_p_{b.lower()}"]), 6) for b in BANDS}
    values.append(
        _value(
            "band",
            models,
            row["band"],
            probabilities[row["band"]],
            probabilities,
            row["band_set"].split("|") if row["band_set"] else [row["band"]],
        )
    )
    metric_values = row["metrics"].split(",")
    metric_sets = row["metric_sets"].split(";")
    for m, v, p, s in zip(METRICS, metric_values, row["metrics_p"], metric_sets, strict=True):
        version, role = chosen(models, "metrics")
        values.append(
            PredictedValue(
                field=f"metric_{m}",
                model=FIELD_MODELS["metrics"],
                version=version,
                role=role,
                value=v,
                probability=round(float(p), 6),
                set=s.split("|") if s else [v],
            )
        )
    values.append(
        _value(
            "cwe",
            models,
            row["cwe"],
            row["cwe_p"],
            detail={"top5": [c for c in row["cwe_top"].split("|") if c]},
        )
    )
    epss: dict[str, JsonValue] = {
        "score": cve_row.get("epss_score"),
        "percentile": cve_row.get("epss_percentile"),
        "date": cve_row["epss_date"].isoformat() if cve_row.get("epss_date") else None,
        "note": EPSS_NOTE,
    }
    values.append(
        _value(
            "exploitation",
            models,
            round(float(row["exploit_p"]), 6),
            row["exploit_p"],
            detail={
                "meaning": "the chance KEV lists this CVE within 180 days of publication, scored at day 0",
                "score": round(float(row["exploit_score"]), 6),
                "percentile": round(float(row["exploit_pct"]), 2),
                "percentile_of": f"every CVE in batch {models.get('batch')}",
                "epss": epss,
            },
        )
    )
    by_day = {str(h): row[f"listed_by_{h}"] for h in (30, 90, 180) if row[f"listed_by_{h}"] is not None}
    if by_day:
        values.append(
            _value(
                "kev_listing",
                models,
                {k: round(float(v), 6) for k, v in by_day.items()},
                detail={"meaning": "the chance of a KEV listing by 30, 90 and 180 days after publication"},
            )
        )
    candidates = [p for p in row["products"].split("|") if p]
    values.append(
        _value(
            "products",
            models,
            candidates,
            detail={
                "meaning": "CPE vendor and product pairs, most likely first; a list to check, not a match"
            },
        )
    )
    made = models.get("made_on")
    return (
        Predictions(
            batch=str(models.get("batch") or ""),
            made_on=date.fromisoformat(made) if isinstance(made, str) else None,
            window=window_of(cve_row.get("published")),
            note=NOTE,
            values=values,
        ),
        None,
    )


def load_models(conn: sa.Connection) -> dict[str, Any] | None:
    """The registry export the loaded bundle carried, or None when it carried none."""
    value = conn.execute(sa.select(db.settings.c.value).where(db.settings.c.key == "models")).scalar()
    return value if isinstance(value, dict) else None
