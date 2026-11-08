"""Units and published rounding, read from a format code.

Every manifest value carries a format code (pct1, int0, day1 and so on). The code fixes two
things: the unit the raw value is stored in, and the rounding step of the published figure in that
unit. The tolerance of the gate is half a step.

A value stored as a fraction (a share, a rate of flights, a difference of two shares) is printed in
percent or in percentage points; the stored unit is still the fraction, and a claim made in percent
is converted only when both sides say so.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Unit = Literal[
    "fraction",
    "percent",
    "dollars",
    "count",
    "years",
    "index points",
    "minutes",
    "hours",
    "days",
    "milliseconds",
    "share of flights",
    "basis points",
    "ratio",
    "none",
]

UNITS: tuple[Unit, ...] = (
    "fraction",
    "percent",
    "dollars",
    "count",
    "years",
    "index points",
    "minutes",
    "hours",
    "days",
    "milliseconds",
    "share of flights",
    "basis points",
    "ratio",
    "none",
)

# Units stored as a fraction of one: they convert to percent by a factor of a hundred.
FRACTIONAL: frozenset[str] = frozenset({"fraction", "share of flights"})


@dataclass(frozen=True)
class FormatSpec:
    unit: Unit
    step: float | None  # the published rounding step in the stored unit; None for text
    numeric: bool = True


def _spec(unit: Unit, step: float) -> FormatSpec:
    return FormatSpec(unit, step)


SPECS: dict[str, FormatSpec] = {
    "int": _spec("count", 1.0),
    "float1": _spec("none", 0.1),
    "float2": _spec("none", 0.01),
    "float3": _spec("none", 0.001),
    "float4": _spec("none", 0.0001),
    "sfloat1": _spec("none", 0.1),
    "sfloat2": _spec("none", 0.01),
    "sfloat3": _spec("none", 0.001),
    "sfloat4": _spec("none", 0.0001),
    "pct0": _spec("fraction", 0.01),
    "pct1": _spec("fraction", 0.001),
    "pct2": _spec("fraction", 0.0001),
    "pct3": _spec("fraction", 0.00001),
    "spct0": _spec("fraction", 0.01),
    "spct1": _spec("fraction", 0.001),
    "spct2": _spec("fraction", 0.0001),
    "pts1": _spec("fraction", 0.001),
    "pts2": _spec("fraction", 0.0001),
    "apts1": _spec("fraction", 0.001),
    "min0": _spec("minutes", 1.0),
    "min1": _spec("minutes", 0.1),
    "min2": _spec("minutes", 0.01),
    "smin1": _spec("minutes", 0.1),
    "smin2": _spec("minutes", 0.01),
    "millions1": _spec("count", 100_000.0),
    "thousands0": _spec("count", 1_000.0),
    "hours0": _spec("hours", 1.0),
    "hours1": _spec("hours", 0.1),
    "days1": _spec("days", 0.1),
    "ms": _spec("milliseconds", 1.0),
    "usd0": _spec("dollars", 1.0),
    "usd2": _spec("dollars", 0.01),
    "susd0": _spec("dollars", 1.0),
    "usdk": _spec("dollars", 100.0),
    "usdm": _spec("dollars", 100_000.0),
    "usdm1": _spec("dollars", 100_000.0),
    "usdb1": _spec("dollars", 100_000_000.0),
    "years1": _spec("years", 0.1),
    "years0": _spec("years", 1.0),
    "beyond1": _spec("years", 0.1),
    "beyond0": _spec("years", 1.0),
    "ratio1": _spec("ratio", 0.1),
    "ratio2": _spec("ratio", 0.01),
    "rate2": _spec("percent", 0.01),
    "srate2": _spec("percent", 0.01),
    "quarter": FormatSpec("none", None, numeric=False),
    "year": FormatSpec("years", 1.0, numeric=False),
    "text": FormatSpec("none", None, numeric=False),
}


def spec(fmt: str) -> FormatSpec:
    if fmt not in SPECS:
        raise KeyError(f"no unit is known for the format {fmt!r}")
    return SPECS[fmt]


class UnitMismatch(ValueError):
    """Two values whose units the catalog cannot reconcile."""


def convert(value: float, from_unit: str, to_unit: str) -> float:
    """Convert between units the catalog allows: a fraction and a percent, and nothing else.

    The same unit converts to itself. Anything else raises, so a share is never compared with a
    dollar amount and a fraction is never silently read as a percent.
    """
    if from_unit == to_unit:
        return value
    if from_unit in FRACTIONAL and to_unit == "percent":
        return value * 100.0
    if from_unit == "percent" and to_unit in FRACTIONAL:
        return value / 100.0
    if {from_unit, to_unit} == {"fraction", "share of flights"}:
        return value
    if from_unit == "basis points" and to_unit in FRACTIONAL:
        return value / 10_000.0
    if from_unit in FRACTIONAL and to_unit == "basis points":
        return value * 10_000.0
    raise UnitMismatch(f"cannot compare a value in {from_unit} with one in {to_unit}")


def step_in(step: float, from_unit: str, to_unit: str) -> float:
    """A rounding step carried into another unit, for a tolerance stated in the claim's unit."""
    return abs(convert(step, from_unit, to_unit))
