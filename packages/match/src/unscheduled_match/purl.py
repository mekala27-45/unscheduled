"""Package URLs: parsed, written back in one canonical form, and turned into the key OSV uses.

Syft writes a purl for every package it can name. The matcher never compares purl strings: it
turns each into (OSV ecosystem, package name, version) the way the advisory databases spell them.
A Go module `pkg:golang/github.com/a/b@v1.2.0` is `Go` / `github.com/a/b` / `1.2.0`; a Maven
artifact `pkg:maven/org.x/y@1.0` is `Maven` / `org.x:y` / `1.0`; a Debian binary package is matched
through its source package, which Syft records in the `upstream` qualifier, in the release named by
the `distro` qualifier (`debian-12` is `Debian:12`).
"""

from __future__ import annotations

import re

from packageurl import PackageURL
from unscheduled_core.model import StrictModel

from unscheduled_match import ecosystems as eco_mod
from unscheduled_match.ecosystems import Ecosystem


class PurlError(ValueError):
    """A string that is not a package URL."""


class PackageKey(StrictModel):
    """What an advisory database calls a component."""

    ecosystem: str  # OSV ecosystem, with the release for Debian (Debian:12)
    name: str  # as the advisory databases spell it
    version: str  # in the form the ecosystem's ranges use (no leading v for Go)
    binary_name: str | None = None  # a Debian binary package matched through its source

    @property
    def base(self) -> str:
        return eco_mod.base_osv_ecosystem(self.ecosystem)


def parse(text: str) -> PackageURL:
    try:
        return PackageURL.from_string(text)
    except ValueError as err:
        raise PurlError(f"not a package URL: {text!r}: {err}") from err


def canonical(text: str) -> str:
    """One spelling per package URL: qualifiers sorted, components encoded once, type lowercased."""
    return parse(text).to_string()


def ecosystem_of(purl: PackageURL) -> Ecosystem | None:
    return eco_mod.BY_PURL_TYPE.get(purl.type)


_DEB_RELEASE = re.compile(r"^debian-(\d+)(?:\.\d+)*$")


def debian_release(qualifiers: dict[str, str]) -> str | None:
    """`distro=debian-12` or `distro=debian-12.8` names the release Debian:12."""
    match = _DEB_RELEASE.match(qualifiers.get("distro", ""))
    return match.group(1) if match else None


def _qualifiers(purl: PackageURL) -> dict[str, str]:
    raw = purl.qualifiers
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, str) and raw:
        out: dict[str, str] = {}
        for pair in raw.split("&"):
            key, _, value = pair.partition("=")
            out[key] = value
        return out
    return {}


def package_key(purl: PackageURL) -> PackageKey | None:
    """The OSV key of a package URL, or None when its type is not one of the six ecosystems.

    A purl without a version has no key: there is nothing to compare a range with.
    """
    eco = ecosystem_of(purl)
    if eco is None or not purl.version:
        return None
    version = purl.version
    namespace = purl.namespace or ""
    if eco is eco_mod.NPM:
        name = f"{namespace}/{purl.name}" if namespace else purl.name
        return PackageKey(ecosystem=eco.osv, name=name, version=version)
    if eco is eco_mod.GO:
        name = f"{namespace}/{purl.name}" if namespace else purl.name
        return PackageKey(ecosystem=eco.osv, name=name, version=version.removeprefix("v"))
    if eco is eco_mod.MAVEN:
        if not namespace:
            return None
        return PackageKey(ecosystem=eco.osv, name=f"{namespace}:{purl.name}", version=version)
    if eco is eco_mod.DEBIAN:
        qualifiers = _qualifiers(purl)
        release = debian_release(qualifiers)
        if release is None or namespace != "debian":
            return None
        source, _, source_version = qualifiers.get("upstream", "").partition("@")
        return PackageKey(
            ecosystem=f"{eco.osv}:{release}",
            name=source or purl.name,
            version=source_version or version,
            binary_name=purl.name if source and source != purl.name else None,
        )
    # PyPI and crates.io have no namespace.
    return PackageKey(ecosystem=eco.osv, name=purl.name, version=version)


def key_of(text: str) -> PackageKey | None:
    return package_key(parse(text))


def component_key(text: str) -> tuple[str, str, str] | None:
    """The package as written in the SBOM, before any source mapping: what both engines list.

    (base OSV ecosystem, name in the advisory spelling, version as the purl gives it). A Debian
    binary package keeps its binary name and version here.
    """
    purl = parse(text)
    eco = ecosystem_of(purl)
    if eco is None or not purl.version:
        return None
    if eco is eco_mod.DEBIAN:
        return eco.osv, purl.name, purl.version
    key = package_key(purl)
    if key is None:
        return None
    return eco.osv, eco_mod.normalize_name(eco, key.name), key.version
