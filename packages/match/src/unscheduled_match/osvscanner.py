"""osv-scanner, the second engine: run offline on the same SBOM and the same OSV files, then read back.

osv-scanner is run with every vulnerability shown (--all-vulns: by default it hides the ones a
database marks unimportant) and every package listed (--all-packages), so the comparison sees what
osv-scanner extracted from the SBOM as well as what it matched. --offline keeps it off the network.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from unscheduled_core.model import StrictModel

from unscheduled_match import ecosystems as eco_mod

FLAGS = (
    "scan",
    "source",
    "--offline",
    "--offline-vulnerabilities",
    "--all-vulns",
    "--all-packages",
    "--format",
    "json",
)


class ScannedPackage(StrictModel):
    ecosystem: str
    name: str
    version: str
    purl: str | None = None
    ids: tuple[str, ...]


class ScanResult(StrictModel):
    sbom: str
    packages: tuple[ScannedPackage, ...]
    exit_code: int


def run(binary: Path, sbom: Path, db_dir: Path, out: Path) -> int:
    """osv-scanner exits 1 when it found vulnerabilities and 0 when it found none; both are answers."""
    env = {**os.environ, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(db_dir)}
    done = subprocess.run(
        [str(binary), *FLAGS, "--output-file", str(out), "-L", str(sbom)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode not in (0, 1) or not out.exists():
        raise RuntimeError(f"osv-scanner failed on {sbom.name} ({done.returncode}): {done.stderr[-2000:]}")
    return done.returncode


def parse(data: dict[str, Any], sbom: str, exit_code: int) -> ScanResult:
    packages: list[ScannedPackage] = []
    for result in data.get("results") or []:
        for item in result.get("packages") or []:
            package = item.get("package") or {}
            packages.append(
                ScannedPackage(
                    ecosystem=str(package.get("ecosystem", "")),
                    name=str(package.get("name", "")),
                    version=str(package.get("version", "")),
                    purl=package.get("purl"),
                    ids=tuple(sorted({str(v["id"]) for v in item.get("vulnerabilities") or []})),
                )
            )
    return ScanResult(sbom=sbom, packages=tuple(packages), exit_code=exit_code)


def read(path: Path, sbom: str, exit_code: int) -> ScanResult:
    return parse(json.loads(path.read_text(encoding="utf-8")), sbom, exit_code)


def comparison_key(ecosystem: str, name: str, version: str) -> tuple[str, str, str]:
    """The key both engines' packages are compared on: base ecosystem, name, version as written.

    Go versions lose the leading v, and names fold the way the ecosystem folds them, so the two
    engines' spellings of one package meet.
    """
    eco = eco_mod.lookup_osv(ecosystem)
    base = eco.osv if eco else eco_mod.base_osv_ecosystem(ecosystem)
    folded = eco_mod.normalize_name(eco, name) if eco else name
    if eco is eco_mod.GO:
        version = version.removeprefix("v")
    return base, folded, version
