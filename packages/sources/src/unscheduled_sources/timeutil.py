"""Time as the sources publish it, read into UTC once.

The sources write timestamps five ways: with Z, with an offset with or without a colon, with no
zone at all (the NVD and older CVE records mean UTC), with three to seven fractional digits, or as a
bare date. Every one is read here into an aware UTC datetime, so no table holds a naive time.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime, timedelta

_FRACTION = re.compile(r"(\.\d{1,6})\d*")
_OFFSET_NO_COLON = re.compile(r"([+-]\d{2})(\d{2})$")


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def iso(value: datetime) -> str:
    """The one way a time is written into a lock, the ledger or a URL: seconds, Z."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: object) -> datetime | None:
    """An aware UTC datetime from any timestamp form the sources use, or None for an empty value."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) == 10:
        day = date.fromisoformat(text)
        return datetime(day.year, day.month, day.day, tzinfo=UTC)
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    text = _FRACTION.sub(r"\1", text, count=1)
    text = _OFFSET_NO_COLON.sub(r"\1:\2", text)
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_day(value: object) -> date | None:
    parsed = parse_ts(value)
    return parsed.date() if parsed is not None else None


def windows(start: datetime, end: datetime, days: int) -> list[tuple[datetime, datetime]]:
    """Consecutive half open windows of at most `days` days covering start to end."""
    if days <= 0:
        raise ValueError("a window has at least one day")
    out: list[tuple[datetime, datetime]] = []
    cursor = start
    while cursor < end:
        upper = min(cursor + timedelta(days=days), end)
        out.append((cursor, upper))
        cursor = upper
    return out
