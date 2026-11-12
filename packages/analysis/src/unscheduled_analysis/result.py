"""One question's result, as it is written to results/backlog/q<n>.json and into the manifest.

Every value carries its unit (the format code it prints with), the population it counts and, when
it has one, its interval. Every table says what its rows are. A departure from the registered plan
is written under `departure` with the reason, never silently absorbed.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

from unscheduled_analysis.bootstrap import Interval

Scalar = float | int | str | None
MIN_CLUSTERS = 5  # filers a cluster bootstrap needs before its interval says anything


def clean(x: Any) -> Any:
    """A number JSON can hold: a NaN or an infinity becomes None, a SQL decimal a float or an int.

    DuckDB sums integers into HUGEINT and averages into DECIMAL, which arrive as Decimal.
    """
    if isinstance(x, Decimal):
        x = int(x) if x == x.to_integral_value() else float(x)
    if isinstance(x, float) and not math.isfinite(x):
        return None
    return x


@dataclass
class Result:
    qid: str
    title: str
    subtitle: str
    plan: dict[str, Any]
    population: str
    window: str
    data_cut: str
    sql: str
    method: str
    values: dict[str, dict[str, Any]] = field(default_factory=dict)
    tables: dict[str, dict[str, Any]] = field(default_factory=dict)
    departures: list[dict[str, str]] = field(default_factory=list)
    family: list[dict[str, Any]] = field(default_factory=list)
    prediction_check: str = ""
    seed: int | None = None

    def value(self, name: str, value: Scalar, fmt: str, population: str, unit: str) -> None:
        if name in self.values:
            raise KeyError(f"{self.qid}.{name} written twice")
        self.values[name] = {"value": clean(value), "fmt": fmt, "population": population, "unit": unit}

    def interval(self, name: str, iv: Interval, fmt: str, population: str, unit: str) -> None:
        """The estimate with its cluster bootstrap interval, or with the reason it has none.

        Resampling filers says nothing about uncertainty when there are only a few of them: with
        one filer every replicate is the estimate itself. Below MIN_CLUSTERS filers the value is
        written without an interval and says why.
        """
        self.value(name, iv.estimate, fmt, population, unit)
        extra: dict[str, Any] = {"n": iv.units, "clusters": iv.clusters, "resamples": iv.resamples}
        low, high = clean(iv.low), clean(iv.high)
        if iv.clusters >= MIN_CLUSTERS and low is not None and high is not None:
            extra.update({"low": low, "high": high})
        else:
            extra["no_interval"] = (
                f"{iv.clusters} filer{'s' if iv.clusters != 1 else ''}, fewer than {MIN_CLUSTERS}: "
                "a cluster bootstrap by filer gives no interval"
            )
        self.values[name].update(extra)

    def table(
        self, name: str, columns: list[str], formats: list[str], rows: list[list[Scalar]], population: str
    ) -> None:
        if len(columns) != len(formats):
            raise ValueError(f"{self.qid}.{name}: columns and formats differ")
        self.tables[name] = {
            "columns": columns,
            "formats": formats,
            "rows": [[clean(c) for c in r] for r in rows],
            "population": population,
        }

    def depart(self, what: str, reason: str) -> None:
        self.departures.append({"what": what, "reason": reason})

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.qid,
            "title": self.title,
            "subtitle": self.subtitle,
            "plan": self.plan,
            "population": self.population,
            "window": self.window,
            "data_cut": self.data_cut,
            "interval": self.plan.get("interval"),
            "seed": self.seed,
            "values": self.values,
            "tables": self.tables,
            "family": self.family,
            "prediction_check": self.prediction_check,
            "method": self.method,
            "sql": self.sql,
        }
        if self.departures:
            out["departure"] = self.departures
        return out

    def write(self, folder: Path) -> Path:
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{self.qid.lower()}.json"
        path.write_text(
            json.dumps(self.as_dict(), indent=1, sort_keys=False, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        return path
