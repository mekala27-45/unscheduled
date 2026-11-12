"""Every question's result into results/backlog/q<n>.json and the manifest part results/parts/backlog.json.

The manifest keys follow backlog.q<n>.<name>; an interval adds <name>_low and <name>_high, a test in
a Benjamini-Hochberg family adds <name>_p_adjusted. Each question has one figure entry with its
title, its subtitle and the SQL that produced its chart, and each table goes in as a manifest table.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from unscheduled_core.manifest import ManifestBuilder

from unscheduled_analysis.result import Result

ORIGIN = "scripts/run_analysis.py"
SOURCE = "lake"


def part(results: list[Result], as_of: str) -> dict[str, Any]:
    m = ManifestBuilder(as_of)
    for r in results:
        prefix = f"backlog.{r.qid.lower()}"
        for name, v in r.values.items():
            population = f"{v['population']} ({v['unit']})"
            m.value(
                f"{prefix}.{name}", v["value"], v["fmt"], origin=ORIGIN, population=population, source=SOURCE
            )
            if "low" in v:
                note = "cluster bootstrap by filer, 2,000 resamples, 95 percent"
                m.value(
                    f"{prefix}.{name}_low",
                    v["low"],
                    v["fmt"],
                    origin=ORIGIN,
                    population=population,
                    source=SOURCE,
                    note=note,
                )
                m.value(
                    f"{prefix}.{name}_high",
                    v["high"],
                    v["fmt"],
                    origin=ORIGIN,
                    population=population,
                    source=SOURCE,
                    note=note,
                )
            if "p_adjusted" in v:
                m.value(
                    f"{prefix}.{name}_p_adjusted",
                    v["p_adjusted"],
                    "float3",
                    origin=ORIGIN,
                    population=population,
                    source=SOURCE,
                    note="Benjamini-Hochberg over the family of this question",
                )
        for name, t in r.tables.items():
            m.table(
                f"{prefix}.{name}",
                t["columns"],
                t["formats"],
                t["rows"],
                origin=ORIGIN,
                population=t["population"],
                source=SOURCE,
            )
        m.figure(
            prefix,
            r.title,
            r.subtitle,
            origin=ORIGIN,
            population=f"{r.population}; {r.window}",
            source=SOURCE,
            sql=r.sql,
            data=f"results/backlog/{r.qid.lower()}.json",
        )
    return m.dump()


def write(results: list[Result], folder: Path, part_path: Path, as_of: str) -> None:
    for r in results:
        r.write(folder)
    part_path.parent.mkdir(parents=True, exist_ok=True)
    part_path.write_text(
        json.dumps(part(results, as_of), indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )
