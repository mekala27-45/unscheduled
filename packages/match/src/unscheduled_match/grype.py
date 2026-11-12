"""Grype on the same SBOMs: what a scanner sees by its default rules, and what CPE matching alone sees.

Grype matches language packages against GitHub advisories by default and falls back to NVD CPE
names only where its configuration says so. The second run turns CPE matching on for every
ecosystem; the matches whose detail is `cpe-match` are what a matcher that depends on NVD CPE names
finds. Only the fields the contrast needs are kept from Grype's JSON.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from unscheduled_core.model import StrictModel

CPE_ON = {
    f"GRYPE_MATCH_{name}_USING_CPES": "true"
    for name in ("JAVA", "JVM", "JAVASCRIPT", "GOLANG", "PYTHON", "RUST", "DPKG", "STOCK", "DOTNET", "RUBY")
}


class GrypeMatch(StrictModel):
    package: str
    version: str
    purl: str | None = None
    vulnerability: str
    cves: tuple[str, ...]
    match_types: tuple[str, ...]
    fix_state: str | None = None


class GrypeRun(StrictModel):
    product: str
    mode: str  # default or cpe
    db_built: str | None = None
    matches: tuple[GrypeMatch, ...]

    def cves(self, match_type: str | None = None) -> set[str]:
        return {c for m in self.matches if match_type is None or match_type in m.match_types for c in m.cves}


def _env(cache_dir: Path, cpe: bool) -> dict[str, str]:
    env = {
        **os.environ,
        "GRYPE_DB_CACHE_DIR": str(cache_dir),
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    }
    if cpe:
        env.update(CPE_ON)
    return env


def update_db(binary: Path, cache_dir: Path) -> dict[str, Any]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(binary), "db", "update"], env=_env(cache_dir, False), check=True, capture_output=True)
    status = subprocess.run(
        [str(binary), "db", "status", "-o", "json"],
        env=_env(cache_dir, False),
        check=True,
        capture_output=True,
        text=True,
    )
    data: dict[str, Any] = json.loads(status.stdout)
    return data


def run(binary: Path, sbom: Path, cache_dir: Path, out: Path, *, cpe: bool) -> None:
    env = {**_env(cache_dir, cpe), "GRYPE_DB_AUTO_UPDATE": "false"}
    subprocess.run(
        [str(binary), f"sbom:{sbom}", "-o", "json", "--file", str(out), "-q"],
        env=env,
        check=True,
        capture_output=True,
    )


def parse(data: dict[str, Any], product: str, mode: str) -> GrypeRun:
    matches: list[GrypeMatch] = []
    for item in data.get("matches") or []:
        vuln = item.get("vulnerability") or {}
        artifact = item.get("artifact") or {}
        ids = [str(vuln.get("id", ""))] + [
            str(r.get("id", "")) for r in item.get("relatedVulnerabilities") or []
        ]
        matches.append(
            GrypeMatch(
                package=str(artifact.get("name", "")),
                version=str(artifact.get("version", "")),
                purl=artifact.get("purl"),
                vulnerability=str(vuln.get("id", "")),
                cves=tuple(sorted({i for i in ids if i.startswith("CVE-")})),
                match_types=tuple(sorted({str(d.get("type", "")) for d in item.get("matchDetails") or []})),
                fix_state=(vuln.get("fix") or {}).get("state"),
            )
        )
    built = ((data.get("descriptor") or {}).get("db") or {}).get("status", {}).get("built")
    matches.sort(key=lambda m: (m.package, m.version, m.vulnerability))
    return GrypeRun(product=product, mode=mode, db_built=built, matches=tuple(matches))


def read(path: Path, product: str, mode: str) -> GrypeRun:
    return parse(json.loads(path.read_text(encoding="utf-8")), product, mode)
