"""Write web/public/data/field.json, the daily counts behind the landing's character field.

    python scripts/build_field.py            # from the lake file, read only

One row per day since 1 January 2024: the CVEs published that day, rejected CVEs left out as in Q1,
and the share of them the NVD analyzed within 30 days. The share is null for a day whose CVEs have
not all had 30 days by the cut, the same censoring gold.mart_backlog_q1 applies. The counts are
descriptive, like Q1, so they cover every window in config/splits.yaml.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LAKE = ROOT / "data" / "lake" / "unscheduled.duckdb"
OUT = ROOT / "web" / "public" / "data" / "field.json"
FROM = "2024-01-01"
SOURCE = "From gold.mart_backlog_q1 in the lake"

QUERY = """
select cast(published as date) as day,
       count(*) as published,
       case when bool_and(analyzed_30d is not null)
            then avg(cast(analyzed_30d as integer)) end as analyzed_30d
from gold.mart_backlog_q1
where published >= cast($start as timestamptz)
group by all
order by day
"""


def field_rows(con: Any, start: str = FROM) -> list[dict[str, Any]]:
    rows = con.execute(QUERY, {"start": f"{start} 00:00:00+00"}).fetchall()
    return [
        {
            "date": day.isoformat(),
            "published": int(published),
            "analyzed_30d": None if share is None else round(float(share), 4),
        }
        for day, published, share in rows
    ]


def build(lake: Path = LAKE, out: Path = OUT) -> dict[str, Any]:
    import duckdb

    con = duckdb.connect(str(lake), read_only=True)
    try:
        con.execute("set TimeZone = 'UTC'").fetchall()
        cut = con.execute("select data_cut from config.lake_build").fetchall()[0][0]
        days = field_rows(con)
    finally:
        con.close()
    field = {"source": SOURCE, "as_of": cut.date().isoformat(), "from": FROM, "days": days}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(field, separators=(",", ":")) + "\n", encoding="utf-8")
    return field


def main() -> int:
    if not LAKE.exists():
        print(f"field: no lake file at {LAKE.relative_to(ROOT)}; build the lake first", file=sys.stderr)
        return 1
    field = build()
    print(f"field: wrote {OUT.relative_to(ROOT)}, {len(field['days'])} days to {field['as_of']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
