"""The committed serving files hold numbers, never NaN: a NaN in the batch stops the serving bundle at
its check against the API, and a NaN among the quantiles makes every percentile of /v1/predict
zero. The exploitation values of a row are empty together, and only for the rows the batch record
names."""

from __future__ import annotations

import json
import math
from pathlib import Path

import polars as pl
import pytest

ROOT = Path(__file__).resolve().parents[2]
SERVING = ROOT / "models" / "serving"
BATCH = SERVING / "predictions.parquet"
RECORD = ROOT / "results" / "models" / "predictions.json"
EXPLOIT = ("exploit_score", "exploit_p", "exploit_pct")

pytestmark = pytest.mark.skipif(not BATCH.exists(), reason="the batch is not written yet")


def test_the_quantiles_predict_reads_are_numbers_in_order() -> None:
    quantiles = json.loads((SERVING / "serving.json").read_text(encoding="utf-8"))["exploit"]["quantiles"]
    assert len(quantiles) == 1001
    assert all(math.isfinite(q) for q in quantiles)
    assert quantiles == sorted(quantiles)


def test_the_batch_holds_no_nan_and_its_unscored_rows_are_the_recorded_ones() -> None:
    table = pl.read_parquet(BATCH)
    floats = [c for c, t in table.schema.items() if t in (pl.Float32, pl.Float64)]
    with_nan = [c for c in floats if table.select(pl.col(c).is_nan().any()).item()]
    assert with_nan == []
    empty = table.filter(pl.col("exploit_score").is_null())
    for column in EXPLOIT:
        assert table.get_column(column).null_count() == empty.height, column
    record = json.loads(RECORD.read_text(encoding="utf-8"))
    named = sorted(c for ids in record["exploitation_unscored"]["cve_ids"].values() for c in ids)
    assert sorted(empty.get_column("cve_id").to_list()) == named
    assert set(empty.get_column("window")) <= {"development"}
