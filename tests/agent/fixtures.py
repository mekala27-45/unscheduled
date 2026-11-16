"""One CVE the agent tests share: CVE-2024-23897 in Jenkins, as its GitHub advisory and its KEV entry
give it, carried by a stand in product, with the sources the graph reads answering as of a time."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from unscheduled_agent import verify
from unscheduled_agent.graph import Match
from unscheduled_agent.schemas import Evidence, ExploitSignal, FixedVersion, KevListing
from unscheduled_retrieval import corpus
from unscheduled_retrieval.chunks import chunk_document
from unscheduled_retrieval.documents import from_kev, from_osv

CVE = "CVE-2024-23897"
AS_OF = datetime(2024, 8, 19, 23, 59, 59, tzinfo=UTC)
GHSA = "ghsa:GHSA-6f9g-cxwr-q5jr"
GHSA_VERSION = "2024-01-24T18:30:00Z"
ADVISORY: dict[str, Any] = {
    "id": "GHSA-6f9g-cxwr-q5jr",
    "modified": GHSA_VERSION,
    "aliases": [CVE],
    "summary": "Arbitrary file read vulnerability through the CLI can lead to RCE",
    "details": "Jenkins has a built in command line interface. Upgrade to 2.442 or LTS 2.426.3.",
    "affected": [
        {
            "package": {"ecosystem": "Maven", "name": "org.jenkins-ci.main:jenkins-core"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "2.426.3"},
                        {"introduced": "2.427"},
                        {"fixed": "2.442"},
                    ],
                }
            ],
        }
    ],
    "references": [{"type": "ADVISORY", "url": "https://www.jenkins.io/security/advisory/2024-01-24/"}],
}
KEV: dict[str, Any] = {
    "cveID": CVE,
    "vendorProject": "Jenkins",
    "product": "Jenkins Command Line Interface (CLI)",
    "vulnerabilityName": "Jenkins Command Line Interface (CLI) Path Traversal Vulnerability",
    "dateAdded": "2024-08-19",
    "shortDescription": "Jenkins CLI contains a path traversal vulnerability.",
    "requiredAction": "Apply mitigations per vendor instructions.",
    "notes": "https://www.jenkins.io/security/advisory/2024-01-24/",
}
KEV_AT = datetime(2024, 8, 19, 14, tzinfo=UTC)
DESCRIPTION = (
    "Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser."
)


def words(text: str) -> int:
    return len(text.split())


def versions() -> list[corpus.Version]:
    return [
        corpus.Version(
            from_osv(ADVISORY, source="ghsa", known_from=GHSA_VERSION),
            datetime(2024, 1, 24, 18, 30, tzinfo=UTC),
        ),
        corpus.Version(from_kev(KEV, catalog_version="d1", known_from=KEV_AT.isoformat()), KEV_AT),
    ]


def documents() -> verify.FrameDocuments:
    return verify.FrameDocuments(corpus.document_frame(versions()))


class FixtureSources:
    """The sources of the graph over the fixture, each answer as of the time asked."""

    def __init__(self, injected: str | None = None) -> None:
        self.docs = documents()
        self.injected = injected

    @property
    def documents(self) -> verify.Documents:
        return self.docs

    def description(self, cve_id: str, at: datetime) -> str | None:
        return DESCRIPTION if cve_id == CVE else None

    def match(self, cve_id: str, at: datetime) -> Match | None:
        return {
            "product": "pipeline-runner",
            "component": "org.jenkins-ci.main:jenkins-core",
            "ecosystem": "Maven",
            "installed_version": "2.426.1",
        }

    def fixed_versions(self, cve_id: str, match: Match | None, at: datetime) -> list[FixedVersion]:
        return [FixedVersion(version="2.426.3", source=GHSA, doc_version=GHSA_VERSION)]

    def predictions(self, cve_id: str, at: datetime) -> dict[str, Any]:
        return {"cwe": {"value": "CWE-22", "model": "fill", "version": "test"}}

    def kev(self, cve_id: str, at: datetime) -> KevListing | None:
        if at < KEV_AT:
            return None
        return KevListing(
            source=f"kev:{CVE}",
            doc_version="d1",
            listed_at=KEV_AT,
            date_added=date(2024, 8, 19),
            vulnerability_name=KEV["vulnerabilityName"],
            vendor_project="Jenkins",
            product=KEV["product"],
        )

    def exploits(self, cve_id: str, at: datetime) -> list[ExploitSignal]:
        return []

    def epss(self, cve_id: str, at: datetime) -> float | None:
        return 0.94

    def retrieve(self, query: str, at: datetime, k: int) -> list[Evidence]:
        out: list[Evidence] = []
        for v in versions():
            if v.known_from > at:
                continue
            for c in chunk_document(v.doc, words):
                text = c.text if self.injected is None else f"{c.text}\n{self.injected}"
                out.append(
                    Evidence(
                        chunk_id=c.chunk_id,
                        doc_id=c.doc_id,
                        version=v.doc.version,
                        sections=list(c.sections),
                        known_from=v.known_from,
                        text=text,
                        score=1.0 / (1 + len(out)),
                    )
                )
        return out[:k]
