"""How complete the lake is: which bronze tables exist, and how much of the NVD change history.

The history is fetched in change date windows of at most 120 days from 1 January 2017. Coverage is
read two ways that must agree: from the fetch ledger (which windows came back to their last page)
and from the data (which months carry events). The lake reports both, so a build on a history still
being fetched says how much of it it stood on.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import duckdb

from unscheduled_lake.db import rows

_HISTORY = re.compile(r"^history (?P<a>[^/\s]+)/(?P<b>\S+) start=(?P<start>\d+)$")
_LAST = re.compile(r"\blast\b")


def _ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def ledger_history(ledger: Path) -> dict[str, Any]:
    """The change history windows the NVD fetcher completed, from data/locks/ledger.jsonl."""
    spans: dict[tuple[datetime, datetime], dict[str, Any]] = {}
    if ledger.exists():
        for line in ledger.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("source") != "nvd" or row.get("status") != "ok":
                continue
            m = _HISTORY.match(str(row.get("window", "")))
            if not m:
                continue
            key = (_ts(m["a"]), _ts(m["b"]))
            span = spans.setdefault(key, {"pages": 0, "rows": 0, "complete": False})
            span["pages"] += 1
            span["rows"] += int(row.get("rows_in") or 0)
            if _LAST.search(str(row.get("note") or "")):
                span["complete"] = True
    complete = sorted(k for k, v in spans.items() if v["complete"])
    covered_days = sum((b - a).total_seconds() for a, b in complete) / 86400.0
    return {
        "windows_seen": len(spans),
        "windows_complete": len(complete),
        "complete_through": complete[-1][1].isoformat() if complete else None,
        "covered_days": round(covered_days, 1),
        "pages": sum(v["pages"] for v in spans.values()),
        "events": sum(v["rows"] for v in spans.values()),
    }


def data_history(con: duckdb.DuckDBPyConnection, start: date, cut: datetime) -> dict[str, Any]:
    """Which months from the history start to the cut carry change events in bronze."""
    found = rows(
        con,
        "select strftime(date_trunc('month', created), '%Y-%m') as m, count(*) "
        "from bronze.nvd_changes group by 1 order by 1",
    )
    by_month = {str(m): int(n) for m, n in found if m is not None}
    months: list[str] = []
    y, mo = start.year, start.month
    while (y, mo) <= (cut.year, cut.month):
        months.append(f"{y:04d}-{mo:02d}")
        y, mo = (y + 1, 1) if mo == 12 else (y, mo + 1)
    with_events = [m for m in months if by_month.get(m, 0) > 0]
    missing = [m for m in months if by_month.get(m, 0) == 0]
    return {
        "months_expected": len(months),
        "months_with_events": len(with_events),
        "months_missing": missing,
        "share_of_months": round(len(with_events) / len(months), 4) if months else 0.0,
        "events": sum(by_month.values()),
        "first_event_month": min(by_month) if by_month else None,
        "last_event_month": max(by_month) if by_month else None,
    }
