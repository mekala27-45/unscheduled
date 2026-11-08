"""OSV affected ranges evaluated in the version scheme of their ecosystem.

The walk is the evaluation algorithm of the OSV schema (IncludedInRanges and BeforeLimits): sort
the events by version, with introduced "0" before every version, and let each event the version has
reached set or clear the state. Versions are compared by precedence through univers, so build
metadata never decides an order (1.2.3+b equals 1.2.3 in SemVer precedence).

SEMVER and ECOSYSTEM ranges are evaluated; a GIT range needs the commit graph and is skipped and
counted, never guessed. Each evaluated range is also written in vers notation, which is how a
finding records the range it matched, and can be built as a univers VersionRange so the property
tests can hold the walk against univers' own containment rules.
"""

from __future__ import annotations

import functools
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, cast

from univers.version_constraint import VersionConstraint
from univers.version_range import RANGE_CLASS_BY_SCHEMES, VersionRange
from univers.versions import InvalidVersion, Version

from unscheduled_match.ecosystems import Ecosystem

EventKind = Literal["introduced", "fixed", "last_affected", "limit"]
EVENT_KINDS: tuple[EventKind, ...] = ("introduced", "fixed", "last_affected", "limit")


class RangeParseError(ValueError):
    """An event version that does not parse in the range's scheme: quarantine rule Q06."""


@dataclass(frozen=True)
class Event:
    kind: EventKind
    value: str


@dataclass(frozen=True)
class ParsedEvent:
    kind: EventKind
    version: Version | None  # None is introduced "0" or a limit of "*"
    text: str
    index: int


@dataclass(frozen=True)
class Interval:
    """One affected stretch: from `start` (None is "0", before every version) to `end` by `end_op`."""

    start: ParsedEvent | None
    end: ParsedEvent | None
    end_op: Literal["<", "<="] | None


def version_class(eco: Ecosystem, range_type: str) -> type[Version]:
    if range_type == "SEMVER":
        return eco.semver
    if range_type == "ECOSYSTEM":
        return eco.native
    raise RangeParseError(f"no version scheme for a {range_type} range")


def parse_version(cls: type[Version], text: str) -> Version:
    try:
        return cls(text)
    except (InvalidVersion, ValueError, TypeError, AttributeError, IndexError) as err:
        raise RangeParseError(f"{text!r} is not a {cls.__name__}") from err


def compare(a: Version, b: Version) -> int:
    """Precedence order. Two versions neither of which sorts before the other are equal here."""
    if a < b:
        return -1
    if b < a:
        return 1
    return 0


def parse_events(events: Sequence[Event], cls: type[Version]) -> list[ParsedEvent]:
    parsed: list[ParsedEvent] = []
    for index, event in enumerate(events):
        if (event.kind == "introduced" and event.value == "0") or (
            event.kind == "limit" and "*" in event.value
        ):
            parsed.append(ParsedEvent(event.kind, None, event.value, index))
        else:
            parsed.append(ParsedEvent(event.kind, parse_version(cls, event.value), event.value, index))
    return parsed


def _order(a: ParsedEvent, b: ParsedEvent) -> int:
    if a.version is None and b.version is None:
        return a.index - b.index
    if a.version is None:
        return -1 if a.kind == "introduced" else 1
    if b.version is None:
        return 1 if b.kind == "introduced" else -1
    by_version = compare(a.version, b.version)
    return by_version if by_version else a.index - b.index


def sorted_events(parsed: Sequence[ParsedEvent]) -> list[ParsedEvent]:
    return sorted(parsed, key=functools.cmp_to_key(_order))


def before_limits(version: Version, parsed: Sequence[ParsedEvent]) -> bool:
    limits = [e for e in parsed if e.kind == "limit"]
    if not limits:
        return True
    return any(e.version is None or compare(version, e.version) < 0 for e in limits)


def is_affected(version: Version, parsed: Sequence[ParsedEvent]) -> bool:
    """IncludedInRanges for one range, as the OSV schema writes it."""
    if not before_limits(version, parsed):
        return False
    vulnerable = False
    for event in sorted_events(parsed):
        if event.kind == "introduced" and (event.version is None or compare(version, event.version) >= 0):
            vulnerable = True
        elif (
            event.kind == "fixed" and event.version is not None and compare(version, event.version) >= 0
        ) or (
            event.kind == "last_affected"
            and event.version is not None
            and compare(version, event.version) > 0
        ):
            vulnerable = False
    return vulnerable


def intervals(parsed: Sequence[ParsedEvent]) -> list[Interval]:
    """The same range as a list of stretches, for writing it in vers notation."""
    out: list[Interval] = []
    start: ParsedEvent | None = None
    open_ = False
    for event in sorted_events(parsed):
        if event.kind == "introduced" and not open_:
            start, open_ = (None if event.version is None else event), True
        elif event.kind == "fixed" and open_:
            out.append(Interval(start, event, "<"))
            open_ = False
        elif event.kind == "last_affected" and open_:
            out.append(Interval(start, event, "<="))
            open_ = False
    if open_:
        out.append(Interval(start, None, None))
    return out


def constraints(parsed: Sequence[ParsedEvent]) -> list[tuple[str, ParsedEvent]]:
    out: list[tuple[str, ParsedEvent]] = []
    for stretch in intervals(parsed):
        if stretch.start is not None:
            out.append((">=", stretch.start))
        if stretch.end is not None and stretch.end_op is not None:
            out.append((stretch.end_op, stretch.end))
    return out


def to_vers(eco: Ecosystem, parsed: Sequence[ParsedEvent]) -> str:
    """The range in vers notation, for example `vers:npm/>=2.0.0|<2.3.1`; `vers:npm/*` for all."""
    stretches = intervals(parsed)
    if len(stretches) == 1 and stretches[0].start is None and stretches[0].end is None:
        return f"vers:{eco.vers_scheme}/*"
    parts = [f"{op}{event.text}" for op, event in constraints(parsed)]
    return f"vers:{eco.vers_scheme}/" + "|".join(parts)


def to_version_range(eco: Ecosystem, parsed: Sequence[ParsedEvent]) -> VersionRange | None:
    """The range as a univers VersionRange, when its scheme's class is the one the events used."""
    range_class = RANGE_CLASS_BY_SCHEMES[eco.vers_scheme]
    scheme_class = cast(type[Version], getattr(range_class, "version_class"))  # noqa: B009
    versions = [(op, e.version) for op, e in constraints(parsed)]
    if any(not isinstance(v, scheme_class) for _, v in versions):
        return None
    stretches = intervals(parsed)
    if len(stretches) == 1 and stretches[0].start is None and stretches[0].end is None:
        return cast(VersionRange, range_class.from_string(f"vers:{eco.vers_scheme}/*"))  # type: ignore[no-untyped-call]
    built = tuple(VersionConstraint(comparator=op, version=v) for op, v in versions if v is not None)
    return range_class(constraints=built)


def fixed_versions(events: Sequence[Event]) -> list[str]:
    return [e.value for e in events if e.kind == "fixed"]
