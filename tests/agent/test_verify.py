"""C5: every claim checked by code. Each kind of fabricated citation is caught (a missing source, a
source unknown at the run time, a fact not in the source, a version that differs by one digit), a
draft whose fields its verified claims do not hold is blocked, and the floor's drafts verify whole.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest
from unscheduled_agent import floor, verify
from unscheduled_agent.schemas import Citation, Claim, Facts, FixedVersion, KevListing
from unscheduled_retrieval import corpus
from unscheduled_retrieval.documents import from_kev, from_osv

AS_OF = datetime(2024, 8, 19, 23, 59, 59, tzinfo=UTC)
GHSA = "ghsa:GHSA-6f9g-cxwr-q5jr"
ADVISORY = {
    "id": "GHSA-6f9g-cxwr-q5jr",
    "modified": "2024-01-24T18:30:00Z",
    "aliases": ["CVE-2024-23897"],
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
KEV = {
    "cveID": "CVE-2024-23897",
    "vendorProject": "Jenkins",
    "product": "Jenkins Command Line Interface (CLI)",
    "vulnerabilityName": "Jenkins Command Line Interface (CLI) Path Traversal Vulnerability",
    "dateAdded": "2024-08-19",
    "shortDescription": "Jenkins CLI contains a path traversal vulnerability.",
    "requiredAction": "Apply mitigations per vendor instructions.",
    "notes": "https://www.jenkins.io/security/advisory/2024-01-24/",
}


def documents() -> verify.FrameDocuments:
    first = datetime(2024, 1, 24, 18, 30, tzinfo=UTC)
    later = from_osv(
        {**ADVISORY, "modified": "2024-09-01T00:00:00Z", "details": "Fixed in 2.426.4 too."},
        source="ghsa",
        known_from="x",
    )
    versions = [
        corpus.Version(from_osv(ADVISORY, source="ghsa", known_from="x"), first),
        corpus.Version(later, datetime(2024, 9, 1, tzinfo=UTC)),
        corpus.Version(
            from_kev(KEV, catalog_version="d1", known_from="x"), datetime(2024, 8, 19, 14, tzinfo=UTC)
        ),
    ]
    return verify.FrameDocuments(corpus.document_frame(versions))


FACTS = Facts(
    cve_id="CVE-2024-23897",
    as_of=AS_OF,
    product="pipeline-runner",
    component="org.jenkins-ci.main:jenkins-core",
    installed_version="2.426.1",
    fixed_versions=[FixedVersion(version="2.426.3", source=GHSA, doc_version="2024-01-24T18:30:00Z")],
    kev=KevListing(
        source="kev:CVE-2024-23897",
        doc_version="d1",
        listed_at=datetime(2024, 8, 19, 14, tzinfo=UTC),
        date_added=date(2024, 8, 19),
        vulnerability_name=KEV["vulnerabilityName"],
        vendor_project="Jenkins",
        product=KEV["product"],
    ),
)


def test_the_floor_drafts_verify_whole() -> None:
    docs = documents()
    for draft in (floor.plan(FACTS), floor.warning(FACTS.model_copy(update={"product": None}))):
        result = verify.check(draft, FACTS, docs)
        assert result.failures == [] and not result.blocked
        assert result.claims_verified == result.claims_drafted and len(result.sha256) == 64


def _fixed(value: str, citation: Citation) -> Claim:
    return Claim(field="fixed_version", value=value, text=f"Fixed in {value}.", citations=[citation])


@pytest.mark.parametrize(
    ("value", "citation", "reason"),
    [
        ("2.426.3", Citation(source="ghsa:GHSA-0000-0000-0000", section="affected"), "missing_source"),
        (
            "2.426.4",
            Citation(source=GHSA, section="details", version="2024-09-01T00:00:00Z"),
            "unknown_at_run_time",
        ),
        ("3.0.0", Citation(source=GHSA, section="affected"), "not_in_source"),
        ("2.426.4", Citation(source=GHSA, section="affected"), "not_in_source"),
        ("2.426", Citation(source=GHSA, section="affected"), "not_in_source"),
        ("2.426.3", Citation(source=GHSA, section="exploit_notes"), "no_such_section"),
        ("2.426.3", Citation(source="state", section="installed_version"), "state_mismatch"),
    ],
)
def test_each_kind_of_fabricated_citation_is_caught(value: str, citation: Citation, reason: str) -> None:
    plan = floor.plan(FACTS)
    forged = plan.model_copy(
        update={"fixed_version": value, "claims": [*plan.claims, _fixed(value, citation)]}
    )
    result = verify.check(forged, FACTS, documents())
    assert [f.reason for f in result.failures] == [reason]
    assert not any(c.field == "fixed_version" and c.citations == [citation] for c in result.draft.claims)
    assert result.blocked == (value != "2.426.3")


def test_a_draft_whose_fields_its_verified_claims_do_not_hold_is_blocked() -> None:
    plan = floor.plan(FACTS)
    stripped = plan.model_copy(update={"claims": [c for c in plan.claims if c.field != "fixed_version"]})
    result = verify.check(stripped, FACTS, documents())
    assert result.blocked and "no verified claim gives the fixed version 2.426.3" in result.reasons
    warning = floor.warning(FACTS).model_copy(update={"claims": []})
    result = verify.check(warning, FACTS, documents())
    assert result.blocked and "no claim of the draft could be verified" in result.reasons


def test_saying_actively_exploited_needs_a_listing_or_exploit_code() -> None:
    warning = floor.warning(FACTS)
    # Two weeks before CISA listed it, with no exploit code seen: the KEV entry was not known yet.
    before = FACTS.model_copy(update={"kev": None, "as_of": datetime(2024, 8, 5, 23, 59, 59, tzinfo=UTC)})
    result = verify.check(warning, before, documents())
    assert (
        result.blocked
        and "the warning says actively exploited and no verified claim shows it" in result.reasons
    )
    assert {f.reason for f in result.failures if f.field == "exploitation"} == {"unknown_at_run_time"}


def test_a_value_is_found_only_whole() -> None:
    assert verify.holds("fixed in 2.426.3.", "2.426.3")
    assert not verify.holds("fixed in 2.426.30", "2.426.3")
    assert not verify.holds("fixed in 12.426.3", "2.426.3")
    assert not verify.holds("anything", "  ")


def test_the_tally_counts_what_reached_a_person() -> None:
    docs = documents()
    good = verify.check(floor.plan(FACTS), FACTS, docs)
    plan = floor.plan(FACTS)
    bad = verify.check(
        plan.model_copy(
            update={"claims": [*plan.claims, _fixed("3.0.0", Citation(source=GHSA, section="affected"))]}
        ),
        FACTS,
        docs,
    )
    tally = verify.tally([(good, True, verify.check(good.draft, FACTS, docs)), (bad, False, None)])
    assert tally.drafts == 2 and tally.citations_failed == 1 and tally.unverified_in_approval_drafts == 0
    assert tally.reasons == {"not_in_source": 1}
