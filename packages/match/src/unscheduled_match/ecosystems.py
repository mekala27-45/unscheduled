"""The six ecosystems the customer's products live in, each with its own version scheme.

A package URL type, an OSV ecosystem name and a univers version class describe the same thing three
ways. This table is the one place they meet. OSV range type SEMVER is compared by SemVer 2.0 whatever
the ecosystem; ECOSYSTEM is compared by the ecosystem's own rules (PEP 440 for PyPI, Maven's
ComparableVersion for Maven, dpkg for Debian, node and cargo semver for npm and crates.io, Go module
semver for Go).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from univers.versions import (
    DebianVersion,
    GolangVersion,
    MavenVersion,
    PypiVersion,
    SemverVersion,
    Version,
)


@dataclass(frozen=True)
class Ecosystem:
    osv: str  # the OSV ecosystem name, as in the all.zip bucket path
    purl_type: str
    vers_scheme: str  # the univers / vers scheme name for a matched range
    native: type[Version]  # the class an ECOSYSTEM range is compared with
    semver: type[Version]  # the class a SEMVER range is compared with
    lockfiles: tuple[str, ...]  # files at a repository root that count as a committed lockfile


NPM = Ecosystem(
    osv="npm",
    purl_type="npm",
    vers_scheme="npm",
    native=SemverVersion,
    semver=SemverVersion,
    lockfiles=("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"),
)
PYPI = Ecosystem(
    osv="PyPI",
    purl_type="pypi",
    vers_scheme="pypi",
    native=PypiVersion,
    semver=SemverVersion,
    lockfiles=("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock"),
)
GO = Ecosystem(
    osv="Go",
    purl_type="golang",
    vers_scheme="golang",
    native=GolangVersion,
    semver=GolangVersion,
    lockfiles=("go.sum",),
)
MAVEN = Ecosystem(
    osv="Maven",
    purl_type="maven",
    vers_scheme="maven",
    native=MavenVersion,
    semver=SemverVersion,
    lockfiles=("gradle.lockfile", "pom.xml"),
)
CRATES = Ecosystem(
    osv="crates.io",
    purl_type="cargo",
    vers_scheme="cargo",
    native=SemverVersion,
    semver=SemverVersion,
    lockfiles=("Cargo.lock",),
)
DEBIAN = Ecosystem(
    osv="Debian",
    purl_type="deb",
    vers_scheme="deb",
    native=DebianVersion,
    semver=SemverVersion,
    lockfiles=(),
)

ALL: tuple[Ecosystem, ...] = (NPM, PYPI, GO, MAVEN, CRATES, DEBIAN)
BY_OSV: dict[str, Ecosystem] = {e.osv: e for e in ALL}
BY_PURL_TYPE: dict[str, Ecosystem] = {e.purl_type: e for e in ALL}

_PEP503 = re.compile(r"[-_.]+")


def base_osv_ecosystem(name: str) -> str:
    """OSV qualifies some ecosystems with a release: `Debian:12` belongs to `Debian`."""
    return name.split(":", 1)[0]


def lookup_osv(name: str) -> Ecosystem | None:
    return BY_OSV.get(base_osv_ecosystem(name))


def normalize_name(eco: Ecosystem, name: str) -> str:
    """The name two records must share to describe the same package in one ecosystem.

    PyPI names compare by PEP 503 (case and runs of `-_.` folded). crates.io treats `-` and `_` as
    the same crate and ignores case. npm names fold case because the purl specification lowercases
    them (Syft writes pkg:npm/jsonstream for JSONStream) while advisories keep the published
    spelling. Go module paths, Maven coordinates and Debian source package names compare exactly.
    """
    if eco is PYPI:
        return _PEP503.sub("-", name).lower()
    if eco is CRATES:
        return name.replace("_", "-").lower()
    if eco is NPM:
        return name.lower()
    return name
