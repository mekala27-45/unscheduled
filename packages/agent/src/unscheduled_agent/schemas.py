"""The typed state a draft is written from, and the two drafts, as Pydantic models.

A draft is a list of claims. Each claim states one fact under a named field with the value it
asserts and the citations that hold it: a document of the corpus by id, version and section, or a
field of the typed state the graph filled by code (the match, the KEV listing, the exploit signal).
The verifier checks every citation by code (step 9): the source exists, was known at the run time,
and holds the value as written. A model fills the same schemas the floor does, under the same rules,
so the two are compared field by field.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

STATE = "state"  # the source id of a fact the graph put in the typed state


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Citation(Strict):
    source: str = Field(description="a corpus document id such as ghsa:GHSA-xxxx-xxxx-xxxx, or state")
    section: str = Field(description="the section of the document, or the field of the typed state")
    version: str | None = Field(
        default=None, description="the document version cited, as the corpus gives it"
    )


ClaimField = Literal[
    "product",
    "component",
    "installed_version",
    "fixed_version",
    "no_fixed_version",
    "vulnerability",
    "exploitation",
    "exploitation_evidence",
    "member_states",
    "action",
]


class Claim(Strict):
    field: ClaimField
    value: str = Field(description="the value the claim asserts, exactly as the source writes it")
    text: str = Field(description="the sentence a person reads")
    citations: list[Citation] = Field(min_length=1)


class FixedVersion(Strict):
    version: str
    source: str
    section: str = "affected"
    doc_version: str | None = None


class KevListing(Strict):
    source: str
    doc_version: str | None = None
    listed_at: datetime
    vulnerability_name: str | None = None
    vendor_project: str | None = None
    product: str | None = None


class ExploitSignal(Strict):
    source: str
    path: str | None = None
    first_seen: datetime


class Evidence(Strict):
    """A retrieved chunk as the drafting nodes see it: fenced as untrusted, labelled with its id."""

    chunk_id: str
    doc_id: str
    version: str
    sections: list[str]
    known_from: datetime
    text: str
    score: float


class Facts(Strict):
    """What the graph knows about one CVE at the run time, filled by code before any draft."""

    cve_id: str
    as_of: datetime
    description: str | None = None
    product: str | None = Field(default=None, description="the stand in product that carries the component")
    component: str | None = None
    ecosystem: str | None = None
    installed_version: str | None = None
    fixed_versions: list[FixedVersion] = Field(default_factory=list)
    kev: KevListing | None = None
    exploits: list[ExploitSignal] = Field(default_factory=list)
    epss: float | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class PatchPlan(Strict):
    kind: Literal["patch_plan"] = "patch_plan"
    cve_id: str
    component: str | None
    installed_version: str | None
    fixed_version: str | None = Field(
        description="the fixed version an advisory states, or null when no source gives one"
    )
    steps: list[str]
    claims: list[Claim]


class EarlyWarning(Strict):
    """The content of an early warning under the CRA, as a draft for a person to file on the ENISA
    Single Reporting Platform. Nothing here sends it."""

    kind: Literal["early_warning"] = "early_warning"
    cve_id: str
    product: str | None
    vulnerability: str
    actively_exploited: bool
    evidence: str
    member_states: str = Field(description="the member states concerned, or not known")
    claims: list[Claim]


Draft = PatchPlan | EarlyWarning
