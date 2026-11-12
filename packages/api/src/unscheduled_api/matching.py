"""POST /v1/match and `unsched match`: one SBOM in, findings out, and only a digest kept.

The document is read as CycloneDX JSON (bomFormat CycloneDX) or SPDX 2 JSON (spdxVersion SPDX-2.x).
Every component is counted; one without a package URL cannot be matched by any engine and is
counted as such (rule Q07 in the lake). The SBOM itself is never written anywhere: the match log
keeps its sha256, its size, the counts, the time taken and the hashed client.

The seam. Matching is packages/match: its `matcher.match` evaluates every OSV and GHSA range in the
ecosystem's own version scheme. The API gives it an AdvisoryStore filled with the advisories that
name the SBOM's packages. A container on Vercel holds no copy of OSV, so those advisories are read
live from the OSV API (querybatch by package, then each record by id); only package names and
ecosystems leave the API, never the document. Tests hand the same matcher a fixed set of records.
Anything that satisfies `Matcher` can stand in, and a deployment whose packages/match lacks the
functions answers matcher-unavailable instead of guessing.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

import httpx
import sqlalchemy as sa
from unscheduled_core.hashing import sha256_bytes

from unscheduled_api import VERSION, db
from unscheduled_api.problems import ProblemError

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
OSV_BATCH = 1000
OSV_WORKERS = 16
CACHE_RECORDS = 5000

Format = Literal["cyclonedx", "spdx"]


@dataclass(frozen=True)
class SbomComponent:
    ref: str
    type: str
    name: str
    version: str | None
    purl: str | None


@dataclass(frozen=True)
class ParsedSbom:
    sha256: str
    size: int
    format: Format
    spec_version: str | None
    components: tuple[SbomComponent, ...]

    @property
    def with_purl(self) -> int:
        return sum(1 for c in self.components if c.purl)

    @property
    def without_purl(self) -> int:
        return len(self.components) - self.with_purl


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


SPDX_VERSION = re.compile(r"^SPDX-2\.[0-9]+$")


def _objects(container: Mapping[str, Any], key: str, where: str) -> list[Mapping[str, Any]]:
    """The list of JSON objects under key, as openapi.json requires; absent is empty, null is refused."""
    if key not in container:
        return []
    value = container[key]
    if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
        raise ProblemError("unsupported-sbom", f"{where} must be a list of objects")
    return list(value)


def _cyclonedx(doc: Mapping[str, Any]) -> list[SbomComponent]:
    out: list[SbomComponent] = []
    stack: list[tuple[Mapping[str, Any], str]] = [
        (c, "components") for c in reversed(_objects(doc, "components", "components"))
    ]
    while stack:
        raw, where = stack.pop()
        out.append(
            SbomComponent(
                ref=_text(raw.get("bom-ref")) or _text(raw.get("name")) or "",
                type=_text(raw.get("type")) or "",
                name=_text(raw.get("name")) or "",
                version=_text(raw.get("version")),
                purl=_text(raw.get("purl")),
            )
        )
        nested = _objects(raw, "components", f"{where}.components")
        stack.extend((c, f"{where}.components") for c in reversed(nested))
    return out


def _spdx(doc: Mapping[str, Any]) -> list[SbomComponent]:
    out: list[SbomComponent] = []
    for raw in _objects(doc, "packages", "packages"):
        purl = None
        for ref in _objects(raw, "externalRefs", "packages.externalRefs"):
            category = str(ref.get("referenceCategory") or "").replace("_", "-").upper()
            if ref.get("referenceType") == "purl" and category in {"PACKAGE-MANAGER", ""}:
                purl = _text(ref.get("referenceLocator"))
                break
        out.append(
            SbomComponent(
                ref=_text(raw.get("SPDXID")) or _text(raw.get("name")) or "",
                type=_text(raw.get("primaryPackagePurpose")) or "package",
                name=_text(raw.get("name")) or "",
                version=_text(raw.get("versionInfo")),
                purl=purl,
            )
        )
    return out


def parse_sbom(data: bytes) -> ParsedSbom:
    """The document read the way openapi.json describes it; anything else is refused by type."""
    try:
        doc = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise ProblemError("malformed-body", f"the body is not JSON: {type(err).__name__}") from err
    if not isinstance(doc, Mapping):
        raise ProblemError("unsupported-sbom", "the body is JSON but not an object; an SBOM is an object")
    if doc.get("bomFormat") == "CycloneDX":
        spec = doc.get("specVersion")
        if not isinstance(spec, str):
            raise ProblemError("unsupported-sbom", "a CycloneDX document names its specVersion as text")
        return ParsedSbom(
            sha256=sha256_bytes(data),
            size=len(data),
            format="cyclonedx",
            spec_version=spec,
            components=tuple(_cyclonedx(doc)),
        )
    spdx = doc.get("spdxVersion")
    if isinstance(spdx, str) and SPDX_VERSION.match(spdx):
        return ParsedSbom(
            sha256=sha256_bytes(data),
            size=len(data),
            format="spdx",
            spec_version=spdx,
            components=tuple(_spdx(doc)),
        )
    raise ProblemError(
        "unsupported-sbom",
        "the document has neither bomFormat CycloneDX nor an spdxVersion of the form SPDX-2.x; "
        "CycloneDX JSON and SPDX 2 JSON are accepted",
    )


@dataclass(frozen=True)
class EngineResult:
    engine: str
    findings: list[dict[str, Any]]
    components_matched: int
    advisories_read: int

    @property
    def distinct_cves(self) -> int:
        cves: set[str] = set()
        for finding in self.findings:
            for key in ("cve_aliases", "upstream_cves"):
                for value in finding.get(key) or []:
                    if isinstance(value, str) and value.startswith("CVE-"):
                        cves.add(value)
        return len(cves)


class Matcher(Protocol):
    def available(self) -> str | None:
        """None when the matcher can run; otherwise why it cannot."""

    def run(self, sbom: ParsedSbom, as_of: datetime) -> EngineResult: ...


class AdvisorySource(Protocol):
    name: str

    def records(self, packages: Iterable[tuple[str, str]]) -> list[dict[str, Any]]:
        """Every OSV record that names one of these (ecosystem, package) pairs."""


@dataclass
class OsvApiAdvisories:
    """The OSV API, read without a key. Records are cached by id and modified time."""

    client: httpx.Client = field(
        default_factory=lambda: httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={
                "User-Agent": f"unscheduled-api/{VERSION} (+https://github.com/mekala27-45/unscheduled)"
            },
        )
    )
    name: str = "api.osv.dev"
    _cache: OrderedDict[str, tuple[str, dict[str, Any]]] = field(default_factory=OrderedDict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _post(self, queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        try:
            response = self.client.post(OSV_QUERYBATCH, json={"queries": queries})
        except httpx.HTTPError as err:
            raise ProblemError(
                "upstream-unavailable", f"the OSV API did not answer ({type(err).__name__})"
            ) from err
        if response.status_code >= 400:
            raise ProblemError("upstream-unavailable", f"the OSV API answered HTTP {response.status_code}")
        results = response.json().get("results")
        return [r if isinstance(r, dict) else {} for r in results or []]

    def _ids(self, packages: list[tuple[str, str]]) -> dict[str, str]:
        found: dict[str, str] = {}
        pending = [{"package": {"ecosystem": eco, "name": name}} for eco, name in packages]
        rounds = 0
        while pending and rounds < 20:
            rounds += 1
            following: list[dict[str, Any]] = []
            for start in range(0, len(pending), OSV_BATCH):
                batch = pending[start : start + OSV_BATCH]
                for query, result in zip(batch, self._post(batch), strict=False):
                    for vuln in result.get("vulns") or []:
                        if isinstance(vuln, dict) and vuln.get("id"):
                            found[str(vuln["id"])] = str(vuln.get("modified") or "")
                    token = result.get("next_page_token")
                    if token:
                        following.append({**query, "page_token": token})
            pending = following
        return found

    def _record(self, vuln_id: str, modified: str) -> dict[str, Any]:
        with self._lock:
            cached = self._cache.get(vuln_id)
            if cached is not None and cached[0] == modified:
                self._cache.move_to_end(vuln_id)
                return cached[1]
        try:
            response = self.client.get(OSV_VULN.format(id=vuln_id))
        except httpx.HTTPError as err:
            raise ProblemError(
                "upstream-unavailable", f"the OSV API did not answer ({type(err).__name__})"
            ) from err
        if response.status_code >= 400:
            raise ProblemError("upstream-unavailable", f"the OSV API answered HTTP {response.status_code}")
        record: dict[str, Any] = response.json()
        with self._lock:
            self._cache[vuln_id] = (modified, record)
            while len(self._cache) > CACHE_RECORDS:
                self._cache.popitem(last=False)
        return record

    def records(self, packages: Iterable[tuple[str, str]]) -> list[dict[str, Any]]:
        wanted = sorted(set(packages))
        if not wanted:
            return []
        ids = self._ids(wanted)
        with ThreadPoolExecutor(max_workers=OSV_WORKERS) as pool:
            return list(pool.map(lambda item: self._record(*item), sorted(ids.items())))


@dataclass
class StaticAdvisories:
    """A fixed set of OSV records, for tests and for matching offline against a local copy."""

    items: Sequence[dict[str, Any]]
    name: str = "static"

    def records(self, packages: Iterable[tuple[str, str]]) -> list[dict[str, Any]]:
        wanted = set(packages)
        out = []
        for record in self.items:
            for affected in record.get("affected") or []:
                package = affected.get("package") or {}
                if (package.get("ecosystem"), package.get("name")) in wanted:
                    out.append(record)
                    break
        return out


class PackageMatcher:
    """packages/match over an advisory source."""

    def __init__(self, advisories: AdvisorySource) -> None:
        self.advisories = advisories

    def available(self) -> str | None:
        try:
            from unscheduled_match import matcher, osv, purl, sbom, store
        except ImportError as err:
            return f"packages/match is not importable here ({err.name})"
        needed = (
            (matcher, "match"),
            (osv, "from_json"),
            (purl, "key_of"),
            (sbom, "Component"),
            (store, "AdvisoryStore"),
        )
        missing = [f"{m.__name__}.{n}" for m, n in needed if not hasattr(m, n)]
        if missing:
            return "packages/match does not expose " + ", ".join(missing)
        return None

    def run(self, sbom: ParsedSbom, as_of: datetime) -> EngineResult:
        from unscheduled_match import matcher, osv, purl
        from unscheduled_match.sbom import Component
        from unscheduled_match.store import AdvisoryStore

        components = [
            Component(bom_ref=c.ref, type=c.type, name=c.name, version=c.version, purl=c.purl)
            for c in sbom.components
            if c.purl
        ]
        packages: set[tuple[str, str]] = set()
        for component in components:
            try:
                key = purl.key_of(component.purl or "")
            except ValueError:
                continue
            if key is not None:
                packages.add((key.ecosystem, key.name))
        records = self.advisories.records(packages)
        advisories = AdvisoryStore()
        for record in records:
            try:
                advisories.add(osv.from_json(record, "osv"))
            except (KeyError, ValueError):
                continue
        result = matcher.match("upload", components, advisories, as_of)
        findings = [json.loads(f.model_dump_json()) for f in result.findings]
        return EngineResult(
            engine=f"unscheduled-match over {self.advisories.name}",
            findings=findings,
            components_matched=int(result.stats.keyed),
            advisories_read=len(records),
        )


@dataclass(frozen=True)
class MatchRun:
    sbom: ParsedSbom
    result: EngineResult
    as_of: datetime
    duration_ms: float


def run_match(matcher: Matcher, sbom: ParsedSbom, *, as_of: datetime | None = None) -> MatchRun:
    """The one code path the API and the CLI both take. Raises matcher-unavailable or upstream problems."""
    reason = matcher.available()
    if reason is not None:
        raise ProblemError("matcher-unavailable", reason)
    when = as_of or datetime.now(UTC)
    started = time.perf_counter()
    result = matcher.run(sbom, when)
    return MatchRun(sbom, result, when, round((time.perf_counter() - started) * 1000.0, 1))


def log_match(
    conn: sa.Connection,
    *,
    at: datetime,
    sbom: ParsedSbom,
    client: str,
    status: str,
    duration_ms: float,
    run: MatchRun | None,
) -> None:
    """One row per uploaded SBOM: its digest, size, counts, timing and hashed client. Never the SBOM."""
    conn.execute(
        sa.insert(db.match_log).values(
            at=at,
            sbom_sha256=sbom.sha256,
            sbom_bytes=sbom.size,
            format=sbom.format,
            spec_version=sbom.spec_version,
            components=len(sbom.components),
            components_without_purl=sbom.without_purl,
            findings=len(run.result.findings) if run else None,
            distinct_cves=run.result.distinct_cves if run else None,
            duration_ms=duration_ms,
            status=status,
            engine=run.result.engine if run else None,
            client=client,
        )
    )
