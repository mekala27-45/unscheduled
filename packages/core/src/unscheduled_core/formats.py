"""Number formats, ported from doorstep with the codes turnaround and ledger added.

A value is stored raw in a manifest with a named format. Every document, page and API response
formats it through this one table, so a number in a document and the same number on the site cannot
be printed two ways.
"""

from __future__ import annotations

import math
from collections.abc import Callable

FormatFn = Callable[[float | int | str | None], str]

# doorstep prints a breakeven past its thirty year horizon as "beyond 30 years".
BREAKEVEN_HORIZON_YEARS = 30


def _num(value: float | int | str | None) -> float:
    if value is None or isinstance(value, str):
        raise TypeError(f"expected a number, got {value!r}")
    return float(value)


def _is_zero(text: str) -> bool:
    digits = text.replace(",", "").lstrip("+-")
    return float(digits) == 0


def _plain(value: float, decimals: int) -> str:
    text = f"{value:,.{decimals}f}"
    # A value that rounds to zero prints without a sign, whatever its sign before rounding.
    return text[1:] if text.startswith("-") and _is_zero(text) else text


def _signed(value: float, decimals: int) -> str:
    text = _plain(value, decimals)
    return f"+{text}" if value > 0 and not _is_zero(text) else text


def fmt_int(value: float | int | str | None) -> str:
    return f"{round(_num(value)):,}"


def _fixed(decimals: int) -> FormatFn:
    def inner(value: float | int | str | None) -> str:
        return _plain(_num(value), decimals)

    return inner


def _signed_fixed(decimals: int) -> FormatFn:
    def inner(value: float | int | str | None) -> str:
        return _signed(_num(value), decimals)

    return inner


def _pct(decimals: int) -> FormatFn:
    def inner(value: float | int | str | None) -> str:
        return f"{_plain(_num(value) * 100.0, decimals)}%"

    return inner


def _signed_pct(decimals: int) -> FormatFn:
    def inner(value: float | int | str | None) -> str:
        return f"{_signed(_num(value) * 100.0, decimals)}%"

    return inner


def _points(decimals: int) -> FormatFn:
    """A difference of two shares, stored as a fraction, printed in percentage points."""

    def inner(value: float | int | str | None) -> str:
        return f"{_signed(_num(value) * 100.0, decimals)} pts"

    return inner


def _plain_points(decimals: int) -> FormatFn:
    """A size in percentage points with no sign: an absolute error, a width."""

    def inner(value: float | int | str | None) -> str:
        return f"{_plain(_num(value) * 100.0, decimals)} pts"

    return inner


def _minutes(decimals: int) -> FormatFn:
    def inner(value: float | int | str | None) -> str:
        return f"{_plain(_num(value), decimals)} min"

    return inner


def _signed_minutes(decimals: int) -> FormatFn:
    def inner(value: float | int | str | None) -> str:
        return f"{_signed(_num(value), decimals)} min"

    return inner


def fmt_millions1(value: float | int | str | None) -> str:
    return f"{_plain(_num(value) / 1_000_000.0, 1)} million"


def fmt_thousands0(value: float | int | str | None) -> str:
    return f"{round(_num(value) / 1_000.0):,} thousand"


def fmt_hours0(value: float | int | str | None) -> str:
    return f"{round(_num(value)):,} h"


def fmt_hours1(value: float | int | str | None) -> str:
    return f"{_plain(_num(value), 1)} h"


def fmt_days1(value: float | int | str | None) -> str:
    return f"{_plain(_num(value), 1)} days"


def fmt_ms0(value: float | int | str | None) -> str:
    return f"{round(_num(value)):,} ms"


def _usd(decimals: int) -> FormatFn:
    def inner(value: float | int | str | None) -> str:
        v = _num(value)
        text = f"${abs(v):,.{decimals}f}"
        return f"-{text}" if v < 0 and not _is_zero(text[1:]) else text

    return inner


def fmt_usd_millions(value: float | int | str | None) -> str:
    """ledger's money format: dollars in millions with one decimal and an M."""
    v = _num(value) / 1_000_000.0
    text = f"${abs(v):,.1f}M"
    return f"-{text}" if v < 0 and not _is_zero(f"{abs(v):.1f}") else text


def fmt_text(value: float | int | str | None) -> str:
    if value is None:
        return "not available"
    return str(value)


def fmt_usd0(value: float | int | str | None) -> str:
    v = _num(value)
    text = f"${abs(v):,.0f}"
    return f"-{text}" if v < 0 and round(v) != 0 else text


def fmt_susd0(value: float | int | str | None) -> str:
    v = _num(value)
    text = f"${abs(v):,.0f}"
    if round(v) == 0:
        return text
    return f"+{text}" if v > 0 else f"-{text}"


def fmt_usd_k(value: float | int | str | None) -> str:
    """Dollars in thousands with one decimal, for medians on dense pages."""
    return f"${_plain(_num(value) / 1_000.0, 1)}k"


def fmt_usd_m1(value: float | int | str | None) -> str:
    return f"${_plain(_num(value) / 1_000_000.0, 1)} million"


def fmt_usd_b1(value: float | int | str | None) -> str:
    return f"${_plain(_num(value) / 1_000_000_000.0, 1)} billion"


def fmt_years1(value: float | int | str | None) -> str:
    return f"{_plain(_num(value), 1)} years"


def fmt_years0(value: float | int | str | None) -> str:
    v = _num(value)
    return f"{round(v):,} years" if round(v) != 1 else "1 year"


def _beyond(decimals: int) -> FormatFn:
    """A breakeven in years.

    One past the horizon is the engine's sentinel for owning never catching up.
    """

    def fmt(value: float | int | str | None) -> str:
        v = _num(value)
        if v > BREAKEVEN_HORIZON_YEARS:
            return f"beyond {BREAKEVEN_HORIZON_YEARS} years"
        return fmt_years1(v) if decimals else fmt_years0(v)

    return fmt


def fmt_ratio2(value: float | int | str | None) -> str:
    return f"{_plain(_num(value), 2)}x"


def fmt_ratio1(value: float | int | str | None) -> str:
    return f"{_plain(_num(value), 1)}x"


def fmt_rate2(value: float | int | str | None) -> str:
    """A mortgage rate stored in percent, printed with two decimals and a percent sign."""
    return f"{_plain(_num(value), 2)}%"


def fmt_srate2(value: float | int | str | None) -> str:
    return f"{_signed(_num(value), 2)} pts"


def fmt_quarter(value: float | int | str | None) -> str:
    if value is None:
        return "not available"
    return str(value)


def fmt_year(value: float | int | str | None) -> str:
    """A calendar year: four digits, no separator."""
    if value is None:
        return "not available"
    return str(round(_num(value)))


FORMATS: dict[str, FormatFn] = {
    "int": fmt_int,
    "float1": _fixed(1),
    "float2": _fixed(2),
    "float3": _fixed(3),
    "float4": _fixed(4),
    "sfloat1": _signed_fixed(1),
    "sfloat2": _signed_fixed(2),
    "sfloat3": _signed_fixed(3),
    "sfloat4": _signed_fixed(4),
    "pct0": _pct(0),
    "pct1": _pct(1),
    "pct2": _pct(2),
    "spct0": _signed_pct(0),
    "spct1": _signed_pct(1),
    "spct2": _signed_pct(2),
    "pts1": _points(1),
    "pts2": _points(2),
    "apts1": _plain_points(1),
    "min0": _minutes(0),
    "min1": _minutes(1),
    "min2": _minutes(2),
    "smin1": _signed_minutes(1),
    "smin2": _signed_minutes(2),
    "millions1": fmt_millions1,
    "thousands0": fmt_thousands0,
    "hours0": fmt_hours0,
    "hours1": fmt_hours1,
    "days1": fmt_days1,
    "ms": fmt_ms0,
    "usd0": fmt_usd0,
    "usd2": _usd(2),
    "usdm": fmt_usd_millions,
    "pct3": _pct(3),
    "susd0": fmt_susd0,
    "usdk": fmt_usd_k,
    "usdm1": fmt_usd_m1,
    "usdb1": fmt_usd_b1,
    "years1": fmt_years1,
    "years0": fmt_years0,
    "beyond1": _beyond(1),
    "beyond0": _beyond(0),
    "ratio1": fmt_ratio1,
    "ratio2": fmt_ratio2,
    "rate2": fmt_rate2,
    "srate2": fmt_srate2,
    "quarter": fmt_quarter,
    "year": fmt_year,
    "text": fmt_text,
}


def format_value(value: float | int | str | None, fmt: str) -> str:
    if fmt not in FORMATS:
        raise KeyError(f"unknown format {fmt!r}")
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return "not available"
    if value is None and fmt != "text":
        return "not applicable"
    return FORMATS[fmt](value)
