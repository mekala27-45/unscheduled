"""The pinned SBOM tools: a download is used only when its digest and the release's own list agree."""

from __future__ import annotations

import hashlib
import re

import pytest
from unscheduled_match import tools

from tests.match import helpers


def test_every_pin_has_a_sha256_for_four_platforms() -> None:
    for pin in tools.PINS:
        assert set(pin.assets) == {"linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64"}
        for name, digest in pin.assets.values():
            assert pin.version in name or pin.name == "osv-scanner"
            assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert (tools.SYFT.version, tools.OSV_SCANNER.version, tools.GRYPE.version) == (
        "1.57.0",
        "2.7.0",
        "0.121.2",
    )


def test_a_matching_asset_passes() -> None:
    data = b"binary"
    digest = hashlib.sha256(data).hexdigest()
    tools.verify(tools.SYFT, "a.tar.gz", digest, data, f"{digest}  a.tar.gz\n")


def test_an_asset_whose_digest_differs_from_the_pin_is_refused() -> None:
    data = b"binary"
    digest = hashlib.sha256(b"something else").hexdigest()
    with pytest.raises(tools.ChecksumMismatch, match="has digest"):
        tools.verify(tools.SYFT, "a.tar.gz", digest, data, f"{digest}  a.tar.gz\n")


def test_a_release_list_that_no_longer_carries_the_pin_is_refused() -> None:
    data = b"binary"
    digest = hashlib.sha256(data).hexdigest()
    with pytest.raises(tools.ChecksumMismatch, match="checksum file lists"):
        tools.verify(tools.GRYPE, "a.tar.gz", digest, data, f"{'0' * 64}  a.tar.gz\n")


def test_checksum_files_are_read_in_both_layouts() -> None:
    text = f"{'a' * 64}  syft_1.57.0_linux_amd64.tar.gz\n{'b' * 64} *osv-scanner_linux_amd64\nnot a line\n"
    assert tools.parse_checksums(text) == {
        "syft_1.57.0_linux_amd64.tar.gz": "a" * 64,
        "osv-scanner_linux_amd64": "b" * 64,
    }


@pytest.mark.skipif(not helpers.OSV_SCANNER.exists(), reason="the tools are not installed")
def test_the_installed_tools_carry_the_pinned_digests() -> None:
    plat = tools.current_platform()
    for pin in tools.PINS:
        stamp = (helpers.ROOT / "tools" / "bin" / f"{pin.name}.sha256").read_text(encoding="utf-8").split()
        assert stamp[0] == pin.asset(plat)[1] and stamp[2] == pin.version
    assert (helpers.ROOT / "tools" / "bin" / ".gitignore").read_text(encoding="utf-8").strip().endswith("*")
