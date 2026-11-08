"""OSV ranges evaluated per ecosystem: the OSV walk against univers' own containment, and fixed cases.

For each ecosystem the property draws distinct versions in its scheme, builds a range of
introduced and fixed (and sometimes last_affected) events over them, shuffles the events (the OSV
walk must sort them), and checks that the walk and univers' VersionRange agree on every boundary and
on random versions. Versions with build metadata are left out: SemVer precedence ignores it while
univers' equality does not, and the walk follows precedence.
"""

from __future__ import annotations

import functools
import random
from collections.abc import Callable

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from univers.versions import Version
from unscheduled_match import ecosystems as eco_mod
from unscheduled_match import ranges as rng
from unscheduled_match.ecosystems import Ecosystem

N = st.integers(min_value=0, max_value=12)
SEMVER = st.builds(
    lambda a, b, c, pre: f"{a}.{b}.{c}{pre}",
    N,
    N,
    N,
    st.sampled_from(["", "", "", "-alpha.1", "-beta.2", "-rc.1", "-0"]),
)
GO = st.builds(lambda v, p: ("v" if p else "") + v, SEMVER, st.booleans())
PYPI = st.builds(
    lambda a, b, c, tail: f"{a}.{b}{c}{tail}",
    N,
    N,
    st.sampled_from(["", ".0", ".1", ".3", ".10"]),
    st.sampled_from(["", "", "rc1", "b2", ".post1", ".dev3", "a1"]),
)
MAVEN = st.builds(
    lambda a, b, c, tail: f"{a}.{b}{c}{tail}",
    N,
    N,
    st.sampled_from(["", ".0", ".2", ".11"]),
    st.sampled_from(["", "", "-SNAPSHOT", ".Final", "-rc1", "-beta-2", "-M3"]),
)
DEBIAN = st.builds(
    lambda epoch, a, b, rev: f"{epoch}{a}.{b}-{rev}",
    st.sampled_from(["", "", "1:"]),
    N,
    N,
    st.sampled_from(["1", "2", "1+deb12u1", "1+deb12u10", "1~deb12u1", "3+b1"]),
)

CASES: list[tuple[Ecosystem, str, st.SearchStrategy[str]]] = [
    (eco_mod.NPM, "SEMVER", SEMVER),
    (eco_mod.NPM, "ECOSYSTEM", SEMVER),
    (eco_mod.CRATES, "SEMVER", SEMVER),
    (eco_mod.GO, "SEMVER", GO),
    (eco_mod.PYPI, "ECOSYSTEM", PYPI),
    (eco_mod.MAVEN, "ECOSYSTEM", MAVEN),
    (eco_mod.DEBIAN, "ECOSYSTEM", DEBIAN),
]


def distinct_sorted(cls: type[Version], texts: list[str]) -> list[tuple[str, Version]]:
    parsed = [(t, cls(t)) for t in texts]
    parsed.sort(key=functools.cmp_to_key(lambda a, b: rng.compare(a[1], b[1])))
    out: list[tuple[str, Version]] = []
    for text, version in parsed:
        if not out or rng.compare(out[-1][1], version) != 0:
            out.append((text, version))
    return out


def build_events(bounds: list[str], start_at_zero: bool, close_with: str, seed: int) -> list[rng.Event]:
    events: list[rng.Event] = []
    opening = not start_at_zero
    if start_at_zero:
        events.append(rng.Event("introduced", "0"))
    for index, bound in enumerate(bounds):
        last = index == len(bounds) - 1
        if opening:
            events.append(rng.Event("introduced", bound))
        else:
            kind = "last_affected" if (last and close_with == "last_affected") else "fixed"
            events.append(rng.Event(kind, bound))  # type: ignore[arg-type]
        opening = not opening
    random.Random(seed).shuffle(events)
    return events


@pytest.mark.parametrize(("eco", "range_type", "strategy"), CASES, ids=[f"{c[0].osv}-{c[1]}" for c in CASES])
def test_the_osv_walk_agrees_with_univers_in_every_scheme(
    eco: Ecosystem, range_type: str, strategy: st.SearchStrategy[str]
) -> None:
    cls = rng.version_class(eco, range_type)

    @settings(max_examples=150, deadline=None)
    @given(
        st.lists(strategy, min_size=1, max_size=7),
        st.lists(strategy, min_size=1, max_size=10),
        st.booleans(),
        st.sampled_from(["fixed", "last_affected"]),
        st.integers(min_value=0, max_value=10_000),
    )
    def check(texts: list[str], probes: list[str], zero: bool, close_with: str, seed: int) -> None:
        bounds = [t for t, _ in distinct_sorted(cls, texts)]
        events = build_events(bounds, zero, close_with, seed)
        parsed = rng.parse_events(events, cls)
        version_range = rng.to_version_range(eco, parsed)
        assert version_range is not None
        for text in [*bounds, *probes]:
            version = cls(text)
            assert rng.is_affected(version, parsed) == (version in version_range), (
                f"{eco.osv} {range_type} {rng.to_vers(eco, parsed)} on {text}"
            )

    check()


def _walk(eco: Ecosystem, events: list[tuple[str, str]], version: str, range_type: str = "SEMVER") -> bool:
    cls = rng.version_class(eco, range_type)
    parsed = rng.parse_events([rng.Event(k, v) for k, v in events], cls)  # type: ignore[arg-type]
    return rng.is_affected(cls(version), parsed)


SPEC_EXAMPLES: list[tuple[list[tuple[str, str]], str, bool]] = [
    ([("introduced", "0")], "99.0.0", True),
    ([("introduced", "0"), ("fixed", "1.0.2")], "1.0.1", True),
    ([("introduced", "0"), ("fixed", "1.0.2")], "1.0.2", False),
    (
        [("introduced", "1.0.0"), ("fixed", "1.0.2"), ("introduced", "3.0.0"), ("fixed", "3.2.5")],
        "2.0.0",
        False,
    ),
    (
        [("introduced", "1.0.0"), ("fixed", "1.0.2"), ("introduced", "3.0.0"), ("fixed", "3.2.5")],
        "3.1.0",
        True,
    ),
    ([("introduced", "1.0.0"), ("last_affected", "1.4.0")], "1.4.0", True),
    ([("introduced", "1.0.0"), ("last_affected", "1.4.0")], "1.4.1", False),
    (
        [("fixed", "3.2.5"), ("introduced", "3.0.0"), ("fixed", "1.0.2"), ("introduced", "1.0.0")],
        "3.0.0",
        True,
    ),
    ([("introduced", "0"), ("limit", "2.0.0")], "1.9.0", True),
    ([("introduced", "0"), ("limit", "2.0.0")], "2.0.0", False),
    ([("introduced", "0"), ("limit", "*")], "7.0.0", True),
]


@pytest.mark.parametrize(("events", "version", "expected"), SPEC_EXAMPLES)
def test_the_examples_of_the_osv_schema(events: list[tuple[str, str]], version: str, expected: bool) -> None:
    assert _walk(eco_mod.NPM, events, version) is expected


def test_build_metadata_does_not_decide_precedence() -> None:
    assert _walk(eco_mod.NPM, [("introduced", "1.2.3"), ("fixed", "2.0.0")], "1.2.3+build.7")
    assert not _walk(eco_mod.NPM, [("introduced", "0"), ("fixed", "1.2.3")], "1.2.3+build.7")


def test_each_scheme_orders_by_its_own_rules() -> None:
    # PEP 440: a release candidate comes before the release, a post release after it.
    assert _walk(eco_mod.PYPI, [("introduced", "0"), ("fixed", "2.0")], "2.0rc1", "ECOSYSTEM")
    assert not _walk(eco_mod.PYPI, [("introduced", "0"), ("fixed", "2.0")], "2.0.post1", "ECOSYSTEM")
    # Maven: a snapshot comes before its release; 2.0 and 2.0.0 are the same version.
    assert _walk(eco_mod.MAVEN, [("introduced", "0"), ("fixed", "2.0")], "2.0-SNAPSHOT", "ECOSYSTEM")
    assert not _walk(eco_mod.MAVEN, [("introduced", "0"), ("fixed", "2.0")], "2.0.0", "ECOSYSTEM")
    # dpkg: a tilde sorts before everything, an epoch outranks the upstream version.
    assert _walk(
        eco_mod.DEBIAN, [("introduced", "0"), ("fixed", "3.0.15-1")], "3.0.15-1~deb12u1", "ECOSYSTEM"
    )
    assert not _walk(eco_mod.DEBIAN, [("introduced", "0"), ("fixed", "2.0-1")], "1:1.0-1", "ECOSYSTEM")
    # Go: a pseudo version sorts before the release it precedes.
    assert _walk(eco_mod.GO, [("introduced", "0"), ("fixed", "0.1.0")], "v0.0.0-20210101000000-abcdefabcdef")


def test_strings_compared_as_text_would_be_wrong_and_the_schemes_are_not() -> None:
    """The dead end of notebook 03: as strings, 1.10.0 sorts before 1.9.0."""
    assert "1.10.0" < "1.9.0"
    assert not _walk(eco_mod.NPM, [("introduced", "0"), ("fixed", "1.9.0")], "1.10.0")


def test_a_range_written_in_vers() -> None:
    cls = rng.version_class(eco_mod.MAVEN, "ECOSYSTEM")
    parsed = rng.parse_events([rng.Event("fixed", "2.15.0"), rng.Event("introduced", "2.0-beta9")], cls)
    assert rng.to_vers(eco_mod.MAVEN, parsed) == "vers:maven/>=2.0-beta9|<2.15.0"
    everything = rng.parse_events([rng.Event("introduced", "0")], cls)
    assert rng.to_vers(eco_mod.MAVEN, everything) == "vers:maven/*"


def test_an_event_that_does_not_parse_in_its_scheme_is_a_range_parse_error() -> None:
    with pytest.raises(rng.RangeParseError):
        rng.parse_events(
            [rng.Event("introduced", "not a version")], rng.version_class(eco_mod.PYPI, "ECOSYSTEM")
        )


def test_a_git_range_has_no_version_scheme() -> None:
    with pytest.raises(rng.RangeParseError):
        rng.version_class(eco_mod.PYPI, "GIT")


ORDERS: list[Callable[[list[rng.Event]], list[rng.Event]]] = [lambda e: e, lambda e: list(reversed(e))]


@pytest.mark.parametrize("order", ORDERS)
def test_unsorted_events_are_sorted_before_the_walk(
    order: Callable[[list[rng.Event]], list[rng.Event]],
) -> None:
    cls = rng.version_class(eco_mod.NPM, "SEMVER")
    events = order([rng.Event("introduced", "1.0.0"), rng.Event("fixed", "1.5.0")])
    parsed = rng.parse_events(events, cls)
    assert rng.is_affected(cls("1.2.0"), parsed)
    assert not rng.is_affected(cls("1.5.0"), parsed)
