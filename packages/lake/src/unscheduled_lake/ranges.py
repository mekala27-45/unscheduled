"""Quarantine rule Q06: does every version an advisory range names parse in its ecosystem's scheme.

An OSV or GitHub advisory lists affected ranges as events (introduced, fixed, last_affected,
limit). A SEMVER range is read as SemVer 2.0 whatever the ecosystem; an ECOSYSTEM range by the
ecosystem's own scheme; a GIT range names commits, not versions, so it is skipped and counted. The
classes are univers's, the same the matcher in packages/match compares versions with, and
tests/lake/test_ranges.py holds this table to the matcher's for the ecosystems both read.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from univers.versions import (
    ComposerVersion,
    DebianVersion,
    GolangVersion,
    InvalidVersion,
    MavenVersion,
    NugetVersion,
    PypiVersion,
    RubygemsVersion,
    SemverVersion,
    Version,
)

# OSV ecosystem name to the class an ECOSYSTEM range is compared with.
NATIVE: dict[str, type[Version]] = {
    "npm": SemverVersion,
    "PyPI": PypiVersion,
    "Go": GolangVersion,
    "Maven": MavenVersion,
    "crates.io": SemverVersion,
    "RubyGems": RubygemsVersion,
    "NuGet": NugetVersion,
    "Packagist": ComposerVersion,
    "Debian": DebianVersion,
}
# SEMVER ranges are SemVer 2.0 everywhere except Go, whose module versions are semver with a v.
SEMVER: dict[str, type[Version]] = {
    name: (GolangVersion if name == "Go" else SemverVersion) for name in NATIVE
}
EVENT_KEYS = ("introduced", "fixed", "last_affected", "limit")


@dataclass(frozen=True)
class RangeProblem:
    advisory_id: str
    ecosystem: str
    package: str
    range_type: str
    version: str
    reason: str


@dataclass(frozen=True)
class RangeCheck:
    ranges: int
    git_ranges: int
    unknown_scheme: int
    problems: tuple[RangeProblem, ...]


def base_ecosystem(name: str) -> str:
    """OSV qualifies some ecosystems with a release (Debian:12); the scheme is the base's."""
    return name.split(":", 1)[0]


def _parses(cls: type[Version], text: str) -> str | None:
    try:
        cls(text)
    except (InvalidVersion, ValueError, TypeError, AttributeError, IndexError) as err:
        return f"{type(err).__name__}: {err}"[:200]
    return None


def check_affected(
    advisory_id: str, affected_json: str | None, ecosystem_hint: str | None = None
) -> RangeCheck:
    """Check every range of one advisory version. A version of 0 means from the beginning and parses."""
    if not affected_json:
        return RangeCheck(0, 0, 0, ())
    try:
        affected: Any = json.loads(affected_json)
    except json.JSONDecodeError as err:
        problem = RangeProblem(advisory_id, ecosystem_hint or "", "", "", "", f"affected is not JSON: {err}")
        return RangeCheck(0, 0, 0, (problem,))
    if isinstance(affected, dict):
        affected = [affected]
    ranges = git = unknown = 0
    problems: list[RangeProblem] = []
    for item in affected if isinstance(affected, list) else []:
        package = item.get("package") or {}
        eco_name = str(package.get("ecosystem") or ecosystem_hint or "")
        eco = base_ecosystem(eco_name)
        name = str(package.get("name") or "")
        for rng in item.get("ranges") or []:
            kind = str(rng.get("type") or "").upper()
            ranges += 1
            if kind == "GIT":
                git += 1
                continue
            table = SEMVER if kind == "SEMVER" else NATIVE
            cls = table.get(eco)
            if cls is None:
                unknown += 1
                continue
            for event in rng.get("events") or []:
                for key in EVENT_KEYS:
                    value = event.get(key)
                    if value is None or str(value) in {"0", "*"}:
                        continue
                    reason = _parses(cls, str(value))
                    if reason is not None:
                        problems.append(RangeProblem(advisory_id, eco_name, name, kind, str(value), reason))
    return RangeCheck(ranges, git, unknown, tuple(problems))


def check_version(
    ecosystem: str | None, range_type: str | None, version: str | None
) -> tuple[str, str | None]:
    """One range version: ("ok", None), ("bad", reason), ("unknown", reason) or ("git", None)."""
    kind = (range_type or "").upper()
    if kind == "GIT":
        return "git", None
    if version is None or version in {"0", "*"}:
        return "ok", None
    eco = base_ecosystem(ecosystem or "")
    table = SEMVER if kind == "SEMVER" else NATIVE
    cls = table.get(eco)
    if cls is None:
        return "unknown", f"no version scheme for the ecosystem {eco!r}"
    reason = _parses(cls, version)
    return ("ok", None) if reason is None else ("bad", reason)
