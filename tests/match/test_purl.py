"""Package URLs: one canonical spelling that survives a round trip, and the OSV key of each ecosystem."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from packageurl import PackageURL
from unscheduled_match import purl

LOWER = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=12)
NAME = st.builds(lambda a, b: f"{a}-{b}" if b else a, LOWER, st.one_of(st.just(""), LOWER))
NUMBER = st.integers(min_value=0, max_value=40)
SEMVER = st.builds(lambda a, b, c: f"{a}.{b}.{c}", NUMBER, NUMBER, NUMBER)
DEB_VERSION = st.builds(
    lambda epoch, up, rev: f"{epoch}{up}-{rev}",
    st.sampled_from(["", "1:", "2:"]),
    SEMVER,
    st.sampled_from(["1", "2+deb12u3", "1~deb12u1", "5+b1"]),
)


@st.composite
def purls(draw: st.DrawFn) -> PackageURL:
    kind = draw(st.sampled_from(["npm", "npm-scoped", "pypi", "golang", "maven", "cargo", "deb"]))
    if kind == "npm":
        return PackageURL(type="npm", name=draw(NAME), version=draw(SEMVER))
    if kind == "npm-scoped":
        return PackageURL(type="npm", namespace="@" + draw(LOWER), name=draw(NAME), version=draw(SEMVER))
    if kind == "pypi":
        return PackageURL(type="pypi", name=draw(NAME), version=draw(SEMVER))
    if kind == "golang":
        return PackageURL(
            type="golang", namespace=f"github.com/{draw(LOWER)}", name=draw(NAME), version="v" + draw(SEMVER)
        )
    if kind == "maven":
        return PackageURL(type="maven", namespace=f"org.{draw(LOWER)}", name=draw(NAME), version=draw(SEMVER))
    if kind == "cargo":
        return PackageURL(type="cargo", name=draw(NAME), version=draw(SEMVER))
    qualifiers = {"arch": draw(st.sampled_from(["arm64", "all"])), "distro": "debian-12.8"}
    if draw(st.booleans()):
        qualifiers["upstream"] = draw(NAME)
    return PackageURL(
        type="deb", namespace="debian", name=draw(NAME), version=draw(DEB_VERSION), qualifiers=qualifiers
    )


@settings(max_examples=300, deadline=None)
@given(purls())
def test_a_purl_round_trips_through_its_canonical_form(value: PackageURL) -> None:
    text = value.to_string()
    once = purl.canonical(text)
    assert purl.canonical(once) == once
    back = purl.parse(once)
    assert (back.type, back.namespace, back.name, back.version) == (
        value.type,
        value.namespace,
        value.name,
        value.version,
    )
    assert back.qualifiers == value.qualifiers


@settings(max_examples=300, deadline=None)
@given(purls())
def test_the_osv_key_survives_the_round_trip(value: PackageURL) -> None:
    text = value.to_string()
    assert purl.key_of(text) == purl.key_of(purl.canonical(text))


def test_qualifier_order_does_not_change_the_canonical_form() -> None:
    a = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u9?distro=debian-12.8&arch=arm64&upstream=glibc"
    b = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u9?upstream=glibc&arch=arm64&distro=debian-12.8"
    assert purl.canonical(a) == purl.canonical(b)


@pytest.mark.parametrize(
    ("text", "ecosystem", "name", "version"),
    [
        ("pkg:npm/%40babel/core@7.23.0", "npm", "@babel/core", "7.23.0"),
        ("pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20"),
        ("pkg:pypi/charset-normalizer@3.4.0", "PyPI", "charset-normalizer", "3.4.0"),
        ("pkg:golang/golang.org/x/net@v0.23.0", "Go", "golang.org/x/net", "0.23.0"),
        (
            "pkg:golang/github.com/avelino/slugify@v0.0.0-20180501145920-855f152bd774",
            "Go",
            "github.com/avelino/slugify",
            "0.0.0-20180501145920-855f152bd774",
        ),
        ("pkg:maven/cn.hutool/hutool-all@5.8.9", "Maven", "cn.hutool:hutool-all", "5.8.9"),
        ("pkg:cargo/anyhow@1.0.86", "crates.io", "anyhow", "1.0.86"),
    ],
)
def test_each_ecosystem_keys_the_way_osv_spells_it(
    text: str, ecosystem: str, name: str, version: str
) -> None:
    key = purl.key_of(text)
    assert key is not None
    assert (key.ecosystem, key.name, key.version) == (ecosystem, name, version)


def test_a_debian_binary_package_is_keyed_by_its_source_and_release() -> None:
    key = purl.key_of("pkg:deb/debian/libc6@2.36-9%2Bdeb12u9?arch=arm64&distro=debian-12.8&upstream=glibc")
    assert key is not None
    assert (key.ecosystem, key.name, key.version, key.binary_name) == (
        "Debian:12",
        "glibc",
        "2.36-9+deb12u9",
        "libc6",
    )


def test_a_debian_source_version_in_upstream_wins_over_the_binary_version() -> None:
    key = purl.key_of(
        "pkg:deb/debian/bsdutils@1%3A2.38.1-5%2Bdeb12u2?arch=arm64&distro=debian-12.8&upstream=util-linux%402.38.1-5%2Bdeb12u2"
    )
    assert key is not None
    assert (key.name, key.version) == ("util-linux", "2.38.1-5+deb12u2")


def test_a_debian_package_built_from_its_own_name_has_no_binary_name() -> None:
    key = purl.key_of("pkg:deb/debian/tar@1.34%2Bdfsg-1.2%2Bdeb12u1?arch=arm64&distro=debian-12.8")
    assert key is not None
    assert (key.name, key.binary_name) == ("tar", None)


def test_a_purl_with_no_version_or_an_unknown_type_has_no_key() -> None:
    assert purl.key_of("pkg:maven/org.projectlombok/lombok") is None
    assert purl.key_of("pkg:gem/rails@7.0.0") is None
    assert purl.key_of("pkg:deb/debian/tar@1.34?arch=arm64") is None


def test_the_component_key_keeps_the_debian_binary_name() -> None:
    assert purl.component_key("pkg:deb/debian/libc6@2.36-9?arch=arm64&distro=debian-12.8&upstream=glibc") == (
        "Debian",
        "libc6",
        "2.36-9",
    )


def test_a_string_that_is_not_a_purl_is_refused() -> None:
    with pytest.raises(purl.PurlError):
        purl.parse("npm:lodash@4.17.20")
