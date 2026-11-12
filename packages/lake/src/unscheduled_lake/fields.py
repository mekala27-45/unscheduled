"""The vocabulary of the facts: every field, every source name, every rule that dates a fact.

silver.cve_fact holds one row per value a source published about a CVE: the CVE, the field, the
source, the value, the time it became known (known_from), the time it stopped being current
(known_to, null while it still is), the rule that dated known_from (dated_by) and whether the fact
predates the NVD change history (pre_history). This module names the parts; the SQL that builds the
facts is in dbt/models, and the tests hold the two to each other.
"""

from __future__ import annotations

from datetime import UTC, datetime

from unscheduled_core.model import StrictModel

HISTORY_START = datetime(2017, 1, 1, tzinfo=UTC)

NVD = "nvd@nist.gov"
CISA_ADP = "CISA-ADP"
CISA_ADP_ORG_ID = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
KEV = "kev"
EPSS = "epss"
CVELIST = "cvelist"
EXPLOIT_SOURCES = ("metasploit", "nuclei")

# Fields that hold a set of values: each value is its own series, with its own known_to.
SET_FIELDS = frozenset({"cwe", "exploit_code"})

FIELDS: dict[str, str] = {
    "nvd_status": "the NVD status (vulnStatus), from the change history and the NVD record",
    "cvss2_vector": "a CVSS 2.0 base vector",
    "cvss30_vector": "a CVSS 3.0 base vector",
    "cvss31_vector": "a CVSS 3.1 base vector",
    "cvss40_vector": "a CVSS 4.0 base vector",
    "cvss2_score": "the base score of the CVSS 2.0 vector, by the cvss library",
    "cvss30_score": "the base score of the CVSS 3.0 vector, by the cvss library",
    "cvss31_score": "the base score of the CVSS 3.1 vector, by the cvss library",
    "cvss40_score": "the base score of the CVSS 4.0 vector, by the cvss library",
    "cvss2_severity": "the band of the CVSS 2.0 score",
    "cvss30_severity": "the band of the CVSS 3.0 score",
    "cvss31_severity": "the band of the CVSS 3.1 score",
    "cvss40_severity": "the band of the CVSS 4.0 score",
    "cwe": "a CWE id or an NVD placeholder (a set field)",
    "cpe_config": "the NVD has a CPE configuration for the CVE",
    "kev_listed": "the CVE is in the CISA KEV catalog",
    "kev_ransomware": "the catalog's known ransomware campaign use",
    "ssvc_exploitation": "the CISA SSVC exploitation decision point",
    "ssvc_automatable": "the CISA SSVC automatable decision point",
    "ssvc_technical_impact": "the CISA SSVC technical impact decision point",
    "exploit_code": "a Metasploit module or Nuclei template names the CVE (a set field, the path)",
    "epss": "the EPSS score on a score date",
    "affected_versions": "the filer's record names affected versions",
    "cve_state": "the CVE List state, PUBLISHED or REJECTED",
    "assigner": "the CNA that filed the CVE, by short name",
}

DATING_RULES: dict[str, str] = {
    "nvd_history": "the NVD change history event that carried the value",
    "nvd_last_modified": "the last modification of the NVD record that carried the value",
    "record_updated": "the last update of the CVE List record that carried the value",
    "first_fetch": "the first fetch by this build that saw the value",
    "before_history": "an NVD value set before the change history began, dated from publication and flagged",
    "kev_commit": "the first kev-data commit that carried the listing, on or just after dateAdded",
    "kev_date_added": "the start of the KEV dateAdded day, in UTC",
    "kev_catalog_version": "the KEV catalog version that first stated the value",
    "git_first_commit": "the first commit of the file, module or template",
    "git_commit": "the commit of the version of the file that carried the value",
    "epss_score_date": "the EPSS score date",
}


class Fact(StrictModel):
    """One row of silver.cve_fact."""

    cve_id: str
    field: str
    source: str
    value: str
    known_from: datetime
    known_to: datetime | None
    dated_by: str
    pre_history: bool = False

    def current_at(self, t: datetime) -> bool:
        """The as-of predicate itself: known at or before t and not ended by t."""
        return self.known_from <= t and (self.known_to is None or self.known_to > t)
