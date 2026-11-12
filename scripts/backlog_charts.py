"""The six backlog charts the console draws, from results/backlog, in the shape the web reads.

    python scripts/backlog_charts.py      # writes results/backlog/charts.json

Every point is a value or a table cell the analysis wrote (scripts/run_analysis.py); nothing is
computed here but the arrangement, and each title is rendered from the question's own values with
the format codes the manifest uses. build_serving_bundle.py copies the file into the serving bundle
as backlog.json, and the API serves it at /v1/backlog. The shape, per question:

    id, title, source, window, unit ("share" draws as a percent), kind ("line" or "bar"),
    x (labels), series [{key, label, slot 1 to 8, values}], rule ({x, label} or null), sql
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from unscheduled_core.formats import FORMATS

FOLDER = ROOT / "results" / "backlog"
CHANGE_MONTH = "2026-04"
CHANGE_LABEL = "15 April 2026, the NVD changes what it analyzes"
FILER_TYPES = (
    "MITRE",
    "vendor",
    "open source project",
    "research or bug bounty platform",
    "national CERT",
    "other",
    "unregistered",
)


def load(qid: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FOLDER / f"{qid}.json").read_text(encoding="utf-8"))
    return data


def show(q: dict[str, Any], name: str) -> str:
    """A value as the manifest prints it."""
    v = q["values"][name]
    return FORMATS[v["fmt"]](v["value"])


def table(q: dict[str, Any], name: str) -> tuple[list[str], list[list[Any]]]:
    t = q["tables"][name]
    return list(t["columns"]), [list(r) for r in t["rows"]]


def column(columns: list[str], rows: list[list[Any]], name: str) -> list[Any]:
    i = columns.index(name)
    return [r[i] for r in rows]


def chart(q: dict[str, Any], **fields: Any) -> dict[str, Any]:
    return {
        "id": q["id"].lower(),
        "source": f"results/backlog/{q['id'].lower()}.json, from the lake as of {q['data_cut'][:10]}",
        "window": q["window"],
        "sql": q["sql"],
        "rule": None,
        **fields,
    }


def q1() -> dict[str, Any]:
    q = load("q1")
    cols, rows = table(q, "monthly")
    months = [str(m)[:7] for m in column(cols, rows, "Month")]
    series = []
    for slot, days in enumerate((7, 30, 90), start=1):
        judged = column(cols, rows, f"Judged at {days} days")
        share = column(cols, rows, f"Within {days} days")
        series.append(
            {
                "key": f"within_{days}d",
                "label": f"Analyzed within {days} days",
                "slot": slot,
                "values": [s if j else None for s, j in zip(share, judged, strict=True)],
            }
        )
    title = (
        f"The NVD analyzed {show(q, 'share_30d_before_2025')} of new CVEs within 30 days before 2025, "
        f"{show(q, 'share_30d_2025_to_change')} from 2025 to the change and "
        f"{show(q, 'share_30d_since_change')} since"
    )
    return chart(
        q,
        title=title,
        unit="share",
        kind="line",
        x=months,
        series=series,
        rule={"x": CHANGE_MONTH, "label": CHANGE_LABEL} if CHANGE_MONTH in months else None,
    )


def q2() -> dict[str, Any]:
    q = load("q2")
    cols, rows = table(q, "by_status")
    statuses = [str(s) for s in column(cols, rows, "NVD status")]
    title = (
        f"Of {show(q, 'cves')} CVEs published since 15 April 2026 the NVD has analyzed "
        f"{show(q, 'share_analyzed')}; {show(q, 'status_deferred')} are deferred"
    )
    return chart(
        q,
        title=title,
        unit="CVEs",
        kind="bar",
        x=statuses,
        series=[
            {"key": "cves", "label": "CVEs", "slot": 1, "values": column(cols, rows, "CVEs")},
            {"key": "kev", "label": "KEV listed", "slot": 2, "values": column(cols, rows, "KEV listed")},
        ],
    )


def q3() -> dict[str, Any]:
    q = load("q3")
    parts = (
        ("share_filer_cvss_any", "Filer CVSS, any version"),
        ("share_filer_cvss3", "Filer CVSS 3.x"),
        ("share_filer_cvss40", "Filer CVSS 4.0"),
        ("share_filer_cwe", "Filer CWE"),
        ("share_affected_versions", "Affected versions"),
        ("share_adp_value", "Any CISA ADP value"),
        ("share_adp_ssvc", "CISA SSVC"),
        ("share_adp_cvss", "CISA CVSS"),
    )
    title = (
        f"Where the NVD has not analyzed, the filer gave a CVSS score for {show(q, 'share_filer_cvss_any')} "
        f"and affected versions for {show(q, 'share_affected_versions')}"
    )
    return chart(
        q,
        title=title,
        unit="share",
        kind="bar",
        x=[label for _, label in parts],
        series=[
            {
                "key": "share",
                "label": "Share of CVEs without NVD analysis",
                "slot": 1,
                "values": [q["values"][name]["value"] for name, _ in parts],
            }
        ],
    )


def q4() -> dict[str, Any]:
    q = load("q4")
    metrics = (
        ("av", "AV"),
        ("ac", "AC"),
        ("pr", "PR"),
        ("ui", "UI"),
        ("s", "S"),
        ("c", "C"),
        ("i", "I"),
        ("a", "A"),
    )
    x = [label for _, label in metrics] + ["Band"]
    values = [q["values"][f"kappa_{m}"]["value"] for m, _ in metrics] + [q["values"]["kappa_band"]["value"]]
    title = (
        f"Filer and NVD vectors agree on attack vector (kappa {show(q, 'kappa_av')}) far more than on "
        f"attack complexity ({show(q, 'kappa_ac')}); on the severity band, {show(q, 'kappa_band')}"
    )
    return chart(
        q,
        title=title,
        unit="kappa",
        kind="bar",
        x=x,
        series=[{"key": "kappa", "label": "Cohen kappa, filer against NVD", "slot": 1, "values": values}],
    )


def q5() -> dict[str, Any]:
    q = load("q5")
    cols, rows = table(q, "by_year")
    series_of: list[tuple[str, str]] = [
        ("Listed within 30 days", "within_30d"),
        ("No NVD analysis at listing", "no_analysis"),
        ("Exploit code before listing", "exploit_first"),
    ]
    title = (
        f"Half of the KEV listed CVEs since 2021 were listed within {show(q, 'median_days_to_listing')}; "
        f"{show(q, 'share_no_nvd_analysis_at_listing')} had no NVD analysis when listed"
    )
    return chart(
        q,
        title=title,
        unit="share",
        kind="bar",
        x=[str(y) for y in column(cols, rows, "Published")],
        series=[
            {"key": key, "label": label, "slot": i, "values": column(cols, rows, label)}
            for i, (label, key) in enumerate(series_of, start=1)
        ],
    )


def q6() -> dict[str, Any]:
    q = load("q6")
    cols, rows = table(q, "monthly_by_filer_type")
    months = sorted({str(m)[:7] for m in column(cols, rows, "Month")})
    index = {m: i for i, m in enumerate(months)}
    present = {str(t) for t in column(cols, rows, "Filer type")}
    kinds = [t for t in FILER_TYPES if t in present] + sorted(present - set(FILER_TYPES))
    values: dict[str, list[float | None]] = {t: [None] * len(months) for t in kinds}
    for month, kind, cves in zip(
        column(cols, rows, "Month"), column(cols, rows, "Filer type"), column(cols, rows, "CVEs"), strict=True
    ):
        values[str(kind)][index[str(month)[:7]]] = cves
    title = (
        f"The ten filers that grew most carry {show(q, 'top10_share_of_growth')} of the growth in monthly "
        f"CVE volume since 2020; {show(q, 'filers_for_half_of_growth')} carry half"
    )
    slot: Callable[[int], int] = lambda i: min(8, i + 1)  # noqa: E731
    return chart(
        q,
        title=title,
        unit="CVEs",
        kind="line",
        x=months,
        series=[
            {"key": kind.replace(" ", "_"), "label": kind, "slot": slot(i), "values": values[kind]}
            for i, kind in enumerate(kinds)
        ],
        rule={"x": CHANGE_MONTH, "label": CHANGE_LABEL} if CHANGE_MONTH in months else None,
    )


def build() -> dict[str, Any]:
    questions = [q1(), q2(), q3(), q4(), q5(), q6()]
    for q in questions:
        for s in q["series"]:
            if len(s["values"]) != len(q["x"]):
                raise SystemExit(
                    f"backlog charts: {q['id']} {s['key']} has {len(s['values'])} values for {len(q['x'])} labels"
                )
    cut = load("q1")["data_cut"]
    return {"data_cut": cut, "made_by": "scripts/backlog_charts.py", "questions": questions}


def main() -> int:
    doc = build()
    out = FOLDER / "charts.json"
    out.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    for q in doc["questions"]:
        print(f"{q['id']}: {q['kind']}, {len(q['x'])} points, {len(q['series'])} series. {q['title']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
