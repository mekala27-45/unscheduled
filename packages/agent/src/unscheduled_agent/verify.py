"""The verifier: every claim of a draft checked by code against what its citations name (C5).

A citation of a document must name a document of the corpus, in a version that was known at the run
time, and a section of that version that holds the claim's value as written: the value must appear
whole, so a version that differs by one digit, or that is the start of a longer one, is not found. A
citation of the typed state must name a field the graph filled by code and agree with its value. Three
fields state a conclusion rather than copy a value, and each has its own rule: a plan says no fixed
version only when the state holds none, a warning says actively exploited only when it cites a KEV
listing or exploit code known by then, and the member states are not known unless a source names
them.

A citation that fails is removed, and a claim left with no citation is removed. The draft that goes on
is the verified one, and its sha256 is the hash an approval must name (C7). A draft is blocked when
what it states in its fields is not what its verified claims hold: a plan whose fixed version or
component no verified claim gives, a warning that says actively exploited without a verified claim of
it, or a draft with no verified claim at all. A blocked draft never reaches a person.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Protocol

import polars as pl
from unscheduled_core.hashing import canonical_json, sha256_text

from unscheduled_agent.schemas import STATE, Citation, Claim, Draft, EarlyWarning, Facts, PatchPlan

ACTIVELY = "actively exploited"
NO_EVIDENCE = "no evidence of exploitation"
NOT_KNOWN = "not known"


@dataclass(frozen=True)
class DocVersion:
    doc_id: str
    version: str
    known_from: datetime
    known_to: datetime | None
    withdrawn: datetime | None
    sections: dict[str, str]


class Documents(Protocol):
    def versions(self, doc_id: str) -> Sequence[DocVersion]: ...


class FrameDocuments:
    """The documents of the corpus (documents.parquet) by id, every version of each."""

    def __init__(self, frame: pl.DataFrame) -> None:
        self.by_id: dict[str, list[DocVersion]] = {}
        for r in frame.sort(["doc_id", "known_from", "version"]).iter_rows(named=True):
            self.by_id.setdefault(r["doc_id"], []).append(
                DocVersion(
                    r["doc_id"],
                    r["version"],
                    r["known_from"],
                    r["known_to"],
                    r["withdrawn"],
                    dict(json.loads(r["sections_json"])),
                )
            )

    def versions(self, doc_id: str) -> Sequence[DocVersion]:
        return self.by_id.get(doc_id, [])


@dataclass(frozen=True)
class Failure:
    field: str
    source: str
    section: str
    reason: str  # missing_source, unknown_at_run_time, no_such_section, not_in_source, state_mismatch


@dataclass
class Result:
    claims_drafted: int
    claims_verified: int
    claims_removed: int
    citations_checked: int
    citations_failed: int
    failures: list[Failure]
    blocked: bool
    reasons: list[str]
    draft: Draft
    sha256: str

    def summary(self) -> dict[str, Any]:
        out = asdict(self)
        out["draft"] = self.draft.model_dump(mode="json")
        return out


def holds(text: str, value: str) -> bool:
    """The value appears whole in the text: not inside a longer word or version."""
    if not value.strip():
        return False
    pattern = r"(?<![0-9A-Za-z])" + re.escape(value) + r"(?![0-9A-Za-z]|\.[0-9A-Za-z])"
    return re.search(pattern, text) is not None


def draft_sha256(draft: Draft) -> str:
    return sha256_text(canonical_json(draft.model_dump(mode="json")))


def _state_values(facts: Facts) -> dict[str, Callable[[], list[str]]]:
    return {
        "cve_id": lambda: [facts.cve_id],
        "product": lambda: [facts.product] if facts.product else [],
        "component": lambda: [facts.component] if facts.component else [],
        "installed_version": lambda: [facts.installed_version] if facts.installed_version else [],
        "ecosystem": lambda: [facts.ecosystem] if facts.ecosystem else [],
        "fixed_versions": lambda: [f.version for f in facts.fixed_versions],
        "exploits": lambda: [s.first_seen.date().isoformat() for s in facts.exploits],
        "kev": lambda: [facts.kev.listed_at.date().isoformat()] if facts.kev else [],
        "description": lambda: [facts.description] if facts.description else [],
    }


def _version_at(
    versions: Sequence[DocVersion], cited: str | None, at: datetime
) -> tuple[DocVersion | None, str]:
    if cited is not None:
        found = next((v for v in versions if v.version == cited), None)
        if found is None:
            return None, "missing_source"
        return (found, "") if found.known_from <= at else (None, "unknown_at_run_time")
    known = [v for v in versions if v.known_from <= at]
    return (known[-1], "") if known else (None, "unknown_at_run_time")


def _check(claim: Claim, citation: Citation, facts: Facts, documents: Documents) -> str | None:
    """None when the citation holds the claim, else the reason it does not."""
    at = facts.as_of
    if citation.source == STATE:
        section = citation.section
        if claim.field == "no_fixed_version":
            return (
                None
                if section == "fixed_versions" and not facts.fixed_versions and claim.value == "none"
                else "state_mismatch"
            )
        if claim.field == "member_states":
            return None if section == "member_states" and claim.value == NOT_KNOWN else "state_mismatch"
        if claim.field == "exploitation":
            exploited = bool(facts.kev or facts.exploits)
            if claim.value == ACTIVELY:
                return None if section in ("exploits", "kev") and exploited else "state_mismatch"
            return None if claim.value == NO_EVIDENCE and not exploited else "state_mismatch"
        values = _state_values(facts).get(section)
        if values is None:
            return "no_such_section"
        if section == "description":
            return None if any(holds(v, claim.value) for v in values()) else "state_mismatch"
        return None if claim.value in values() else "state_mismatch"
    versions = documents.versions(citation.source)
    if not versions:
        return "missing_source"
    version, reason = _version_at(versions, citation.version, at)
    if version is None:
        return reason
    if version.withdrawn is not None and version.withdrawn <= at:
        return "unknown_at_run_time"
    if claim.field == "exploitation":
        listed = citation.source.startswith("kev:") and citation.source.removeprefix("kev:") == facts.cve_id
        return None if claim.value == ACTIVELY and listed else "not_in_source"
    text = version.sections.get(citation.section)
    if text is None:
        return "no_such_section"
    return None if holds(text, claim.value) else "not_in_source"


def _blocked(draft: Draft, verified: Sequence[Claim]) -> list[str]:
    by_field: dict[str, set[str]] = {}
    for c in verified:
        by_field.setdefault(c.field, set()).add(c.value)
    reasons: list[str] = []
    if not verified:
        reasons.append("no claim of the draft could be verified")
    if isinstance(draft, PatchPlan):
        if draft.fixed_version is not None and draft.fixed_version not in by_field.get(
            "fixed_version", set()
        ):
            reasons.append(f"no verified claim gives the fixed version {draft.fixed_version}")
        if draft.fixed_version is None and "none" not in by_field.get("no_fixed_version", set()):
            reasons.append("the plan gives no fixed version and no verified claim says none is known")
        if draft.component is not None and draft.component not in by_field.get("component", set()):
            reasons.append(f"no verified claim names the component {draft.component}")
    if isinstance(draft, EarlyWarning):
        if draft.actively_exploited and ACTIVELY not in by_field.get("exploitation", set()):
            reasons.append("the warning says actively exploited and no verified claim shows it")
        if draft.member_states not in by_field.get("member_states", set()):
            reasons.append("no verified claim gives the member states")
    return reasons


def check(draft: Draft, facts: Facts, documents: Documents) -> Result:
    failures: list[Failure] = []
    verified: list[Claim] = []
    checked = 0
    for claim in draft.claims:
        kept: list[Citation] = []
        for citation in claim.citations:
            checked += 1
            reason = _check(claim, citation, facts, documents)
            if reason is None:
                kept.append(citation)
            else:
                failures.append(Failure(claim.field, citation.source, citation.section, reason))
        if kept:
            verified.append(claim.model_copy(update={"citations": kept}))
    clean = draft.model_copy(update={"claims": verified})
    reasons = _blocked(draft, verified)
    return Result(
        claims_drafted=len(draft.claims),
        claims_verified=len(verified),
        claims_removed=len(draft.claims) - len(verified),
        citations_checked=checked,
        citations_failed=len(failures),
        failures=failures,
        blocked=bool(reasons),
        reasons=reasons,
        draft=clean,
        sha256=draft_sha256(clean),
    )


@dataclass
class Tally:
    """C5 over many drafts: the counts results/agent/c5.json reports."""

    drafts: int = 0
    claims_drafted: int = 0
    claims_verified: int = 0
    claims_removed: int = 0
    drafts_blocked: int = 0
    citations_failed: int = 0
    unverified_in_approval_drafts: int = 0
    reasons: dict[str, int] = field(default_factory=dict)

    def add(self, result: Result, reached_approval: bool, recheck: Result | None = None) -> None:
        self.drafts += 1
        self.claims_drafted += result.claims_drafted
        self.claims_verified += result.claims_verified
        self.claims_removed += result.claims_removed
        self.drafts_blocked += int(result.blocked)
        self.citations_failed += result.citations_failed
        for f in result.failures:
            self.reasons[f.reason] = self.reasons.get(f.reason, 0) + 1
        if reached_approval and recheck is not None:
            self.unverified_in_approval_drafts += recheck.citations_failed


def tally(results: Iterable[tuple[Result, bool, Result | None]]) -> Tally:
    out = Tally()
    for result, reached, recheck in results:
        out.add(result, reached, recheck)
    return out
