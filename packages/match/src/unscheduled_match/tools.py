"""The three SBOM tools, pinned by version and by the SHA-256 of every release asset.

Syft writes the SBOMs, osv-scanner is the second engine and Grype is the CPE contrast. Each binary
comes from its GitHub release. The checksums below were read from each release's own checksum file on
7 November 2026; a download is accepted only when its digest equals the pinned value and the
release's checksum file still lists that same value. Either mismatch stops the build.
"""

from __future__ import annotations

import hashlib
import io
import os
import platform
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path

import httpx

RELEASES = "https://github.com"


@dataclass(frozen=True)
class ToolPin:
    name: str
    repo: str
    version: str
    checksums_asset: str
    assets: dict[str, tuple[str, str]]  # platform -> (asset name, sha256)
    archive: bool  # a tar.gz holding the binary, or the bare binary

    def asset(self, plat: str) -> tuple[str, str]:
        if plat not in self.assets:
            raise KeyError(f"{self.name} {self.version} has no pinned asset for {plat}")
        return self.assets[plat]

    def url(self, asset_name: str) -> str:
        return f"{RELEASES}/{self.repo}/releases/download/v{self.version}/{asset_name}"


SYFT = ToolPin(
    name="syft",
    repo="anchore/syft",
    version="1.57.0",
    checksums_asset="syft_1.57.0_checksums.txt",
    assets={
        "linux_amd64": (
            "syft_1.57.0_linux_amd64.tar.gz",
            "9c077a7d43029b3b13e98a8db720661e700c4d58db6352153a06395ae4a2a704",
        ),
        "linux_arm64": (
            "syft_1.57.0_linux_arm64.tar.gz",
            "410cbfa0ae0f63246bc0057843760b1de2833cd23919e025e368fd7681308cdb",
        ),
        "darwin_amd64": (
            "syft_1.57.0_darwin_amd64.tar.gz",
            "f0e8568a9429ac1c8e4ae9e9c399fede5fcd09e4a7348b47b0532baf1c6500c1",
        ),
        "darwin_arm64": (
            "syft_1.57.0_darwin_arm64.tar.gz",
            "17012a5a110323bb1069e513a8665f1ae445905c56b4e3f9a9df4f95c5bb6161",
        ),
    },
    archive=True,
)

OSV_SCANNER = ToolPin(
    name="osv-scanner",
    repo="google/osv-scanner",
    version="2.7.0",
    checksums_asset="osv-scanner_SHA256SUMS",
    assets={
        "linux_amd64": (
            "osv-scanner_linux_amd64",
            "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b",
        ),
        "linux_arm64": (
            "osv-scanner_linux_arm64",
            "4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7",
        ),
        "darwin_amd64": (
            "osv-scanner_darwin_amd64",
            "e82c5df7ab0a42dff29a1cd0660711447b56b4c0483ff66ad8634df10fd81a45",
        ),
        "darwin_arm64": (
            "osv-scanner_darwin_arm64",
            "d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b",
        ),
    },
    archive=False,
)

GRYPE = ToolPin(
    name="grype",
    repo="anchore/grype",
    version="0.121.2",
    checksums_asset="grype_0.121.2_checksums.txt",
    assets={
        "linux_amd64": (
            "grype_0.121.2_linux_amd64.tar.gz",
            "9c8965ced9df657e5e851c14021bae838802f711edd7a48f9bc3c923a8d28f12",
        ),
        "linux_arm64": (
            "grype_0.121.2_linux_arm64.tar.gz",
            "d7d2e160255b0f087280feabf6f213cf4c45d475690f3f1fe5dc336eb1037bf0",
        ),
        "darwin_amd64": (
            "grype_0.121.2_darwin_amd64.tar.gz",
            "1a748df28f72e841dea5c6a19c736b61a79c3e81dc376e0c18e1ab0d274cfe08",
        ),
        "darwin_arm64": (
            "grype_0.121.2_darwin_arm64.tar.gz",
            "3633c113d81ec1460b0520e23633d72a25caae62875fd48a8b0e4f22dcc7c704",
        ),
    },
    archive=True,
)

PINS: tuple[ToolPin, ...] = (SYFT, OSV_SCANNER, GRYPE)


class ChecksumMismatch(RuntimeError):
    """A downloaded asset, or the release's own checksum file, disagrees with the pin."""


def current_platform() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if system not in {"linux", "darwin"} or arch is None:
        raise RuntimeError(f"no pinned SBOM tools for {system} {machine}")
    return f"{system}_{arch}"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_checksums(text: str) -> dict[str, str]:
    """The `<sha256>  <file>` lines every one of the three releases publishes."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and len(parts[0]) == 64:
            table[parts[1].lstrip("*")] = parts[0].lower()
    return table


def verify(pin: ToolPin, asset_name: str, expected: str, data: bytes, checksums_text: str) -> None:
    listed = parse_checksums(checksums_text).get(asset_name)
    if listed != expected:
        raise ChecksumMismatch(
            f"{pin.name} {pin.version}: the release checksum file lists {listed} for {asset_name}, "
            f"the pin is {expected}"
        )
    actual = sha256_hex(data)
    if actual != expected:
        raise ChecksumMismatch(
            f"{pin.name} {pin.version}: {asset_name} has digest {actual}, the pin is {expected}"
        )


def binary_from_archive(pin: ToolPin, data: bytes) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            if member.isfile() and Path(member.name).name == pin.name:
                handle = archive.extractfile(member)
                if handle is not None:
                    return handle.read()
    raise ChecksumMismatch(f"{pin.name} {pin.version}: the verified archive holds no {pin.name} binary")


def ensure_ignored(bin_dir: Path) -> None:
    """tools/bin holds downloads, never anything to commit."""
    marker = bin_dir / ".gitignore"
    if not marker.exists():
        marker.write_text("# Downloaded by scripts/make_sboms.py; never committed.\n*\n", encoding="utf-8")


def install(pin: ToolPin, bin_dir: Path, client: httpx.Client, plat: str | None = None) -> Path:
    """Download, verify and install one tool. An installed binary whose digest is recorded is reused."""
    plat = plat or current_platform()
    asset_name, expected = pin.asset(plat)
    bin_dir.mkdir(parents=True, exist_ok=True)
    ensure_ignored(bin_dir)
    target = bin_dir / pin.name
    stamp = bin_dir / f"{pin.name}.sha256"
    if target.exists() and stamp.exists() and stamp.read_text(encoding="utf-8").split()[0] == expected:
        return target
    checksums = client.get(pin.url(pin.checksums_asset), follow_redirects=True)
    checksums.raise_for_status()
    response = client.get(pin.url(asset_name), follow_redirects=True)
    response.raise_for_status()
    verify(pin, asset_name, expected, response.content, checksums.text)
    binary = binary_from_archive(pin, response.content) if pin.archive else response.content
    tmp = target.with_suffix(".part")
    tmp.write_bytes(binary)
    tmp.chmod(tmp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    os.replace(tmp, target)
    stamp.write_text(f"{expected}  {asset_name}  {pin.version}\n", encoding="utf-8")
    return target


def install_all(bin_dir: Path, client: httpx.Client) -> dict[str, Path]:
    return {pin.name: install(pin, bin_dir, client) for pin in PINS}
