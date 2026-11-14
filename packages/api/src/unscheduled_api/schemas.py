"""Every response the API sends, as a strict model. The OpenAPI schema and the web client come from these.

Each one carries the statement and the data version: the bundle the answer was read from, named by
its release tag and the first twelve hex digits of its manifest digest, or "none" before the first
load. A CVE answer gives every field with the source that published it and the time it became known,
because a value without its source and date is the thing this product exists to replace.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, ConfigDict, Field, JsonValue
from unscheduled_core.model import StrictModel


def _utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


# Every time the API writes is in UTC, whatever time zone the database session answered in.
UtcDatetime = Annotated[datetime, AfterValidator(_utc)]


class Envelope(StrictModel):
    statement: str
    data_version: str


# CVEs ------------------------------------------------------------------------------------------


class FieldValue(StrictModel):
    value: JsonValue
    source: str | None
    known_from: UtcDatetime | None
    rule: str


class PredictedValue(StrictModel):
    """One predicted field with the model that made it and its uncertainty. A prediction is never an
    NVD value, and every response that carries one says so."""

    field: str
    model: str
    version: int | None
    role: str | None
    value: JsonValue
    probability: float | None = None
    probabilities: dict[str, float] | None = None
    set: list[str] | None = None
    detail: dict[str, JsonValue] | None = None


class Predictions(StrictModel):
    batch: str
    made_on: date | None
    window: str | None
    note: str
    values: list[PredictedValue]


class CveRecord(Envelope):
    cve_id: str
    as_of: date | None
    known: bool
    fields: dict[str, FieldValue]
    links: dict[str, str]
    note: str | None = None
    predictions: Predictions | None = None
    predictions_note: str | None = None


class CveSummary(StrictModel):
    cve_id: str
    published: UtcDatetime | None
    last_modified: UtcDatetime | None
    nvd_status: str | None
    nvd_status_since: UtcDatetime | None
    filer: str | None
    filer_type: str | None
    cwes: list[str]
    filer_cvss31_score: float | None
    filer_cvss31_band: str | None
    filer_cvss40_score: float | None
    filer_cvss40_band: str | None
    nvd_cvss31_score: float | None
    nvd_cvss31_band: str | None
    kev_date_added: date | None
    epss_score: float | None
    exploit_first_seen: date | None
    has_cpe: bool | None
    predicted_band: str | None = None


class CvePage(Envelope):
    items: list[CveSummary]
    limit: int
    next_cursor: str | None
    filters: dict[str, JsonValue]


class PredictRequest(StrictModel):
    """A description and what a filer would give at publication, scored as a CVE at its day 0. No
    value is coerced: a number sent as text or a boolean sent as a number is refused."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    description: Annotated[str, Field(min_length=20, max_length=4000)]
    filer: Annotated[str | None, Field(max_length=120)] = None
    filer_type: Annotated[str | None, Field(max_length=60)] = None
    cvss31_vector: Annotated[str | None, Field(max_length=120, pattern=r"^CVSS:3\.1/[A-Z:/]+$")] = None
    cwes: Annotated[list[Annotated[str, Field(pattern=r"^CWE-[0-9]{1,5}$")]], Field(max_length=10)] = Field(
        default_factory=list
    )
    vendor: Annotated[str | None, Field(max_length=120)] = None
    product: Annotated[str | None, Field(max_length=120)] = None
    exploit_code: bool = False
    reserved_days: Annotated[int | None, Field(ge=0, le=36500)] = None


class ModelsDocument(Envelope):
    """The registry export the loaded bundle carried, with the evidence of how each model was chosen
    and judged; models is null when the bundle carried none."""

    models: dict[str, JsonValue] | None
    note: str


class PredictResponse(Envelope):
    made_at: UtcDatetime
    note: str
    values: list[PredictedValue]


class TimelineEvent(StrictModel):
    event_id: str
    at: UtcDatetime
    kind: str
    source: str | None
    detail: dict[str, JsonValue]


class Timeline(Envelope):
    cve_id: str
    published: UtcDatetime | None
    events: list[TimelineEvent]


# The backlog, the products and the exposure ----------------------------------------------------


class Backlog(Envelope):
    backlog: JsonValue


class Product(StrictModel):
    product_id: str
    name: str
    attributes: dict[str, JsonValue]


class Products(Envelope):
    products: list[Product]


class CveAsOf(StrictModel):
    """A CVE named by the product's findings, as it was known at the end of the snapshot day."""

    cve_id: str
    in_slice: bool
    known: bool
    nvd_status: str | None
    nvd_cvss31_band: str | None
    filer_cvss31_band: str | None
    filer_cvss40_band: str | None
    kev_listed: bool
    exploit_code_seen: bool


class ExposureFinding(StrictModel):
    finding_id: str
    cve_ids: list[str]
    attributes: dict[str, JsonValue]


class ExposureSummary(StrictModel):
    """Counts of findings say findings; counts of CVEs are of the distinct CVEs the findings name."""

    findings: int
    findings_without_cve: int
    findings_fix_available: int | None
    distinct_cves: int
    cves_by_nvd_status: dict[str, int]
    cves_kev_listed: int
    cves_with_exploit_code: int


class Exposure(Envelope):
    product: Product
    as_of_requested: str
    snapshot: date
    snapshots: list[date]
    summary: ExposureSummary
    findings: list[ExposureFinding]
    cves: list[CveAsOf]


# Matching --------------------------------------------------------------------------------------


class SbomSummary(StrictModel):
    sha256: str
    bytes: int
    format: Literal["cyclonedx", "spdx"]
    spec_version: str | None
    components: int
    with_purl: int
    without_purl: int


class MatchCounts(StrictModel):
    findings: int
    distinct_cves: int
    components_matched: int
    advisories_read: int


class MatchResponse(Envelope):
    sbom: SbomSummary
    engine: str
    as_of: UtcDatetime
    findings: list[dict[str, JsonValue]]
    counts: MatchCounts
    duration_ms: float
    stored: str


# The sync --------------------------------------------------------------------------------------


class SyncChunk(StrictModel):
    table: str
    offset: int
    rows_in: int
    rows_changed: int
    rows_total: int


class SyncResponse(Envelope):
    status: Literal["current", "more", "done"]
    detail: str
    target: str | None
    step: str | None
    step_index: int | None
    steps: int
    chunk: SyncChunk | None
    chunks_done: int | None
    chunks_total: int | None
    storage_bytes: int | None
    storage_ceiling_bytes: int
    checked_release: bool


# Health and meta -------------------------------------------------------------------------------


class DatabaseFacts(StrictModel):
    configured: bool
    variable: str | None
    variables_found: list[str]
    reachable: bool
    schema_name: str
    migration: str | None
    server_version: str | None
    pgvector_available: bool | None
    pgvector_installed: bool | None
    database_size_bytes: int | None
    storage_ceiling_mb: int
    storage_ceiling_bytes: int
    storage_share_used: float | None
    error: str | None


class LastSync(StrictModel):
    at: UtcDatetime
    status: str
    step: str | None
    bundle: str | None


class DataFacts(StrictModel):
    data_version: str
    tag: str | None
    generated_at: str | None
    loaded_at: str | None
    lake_digest: str | None
    loading: str | None
    counts: dict[str, int] | None
    freshness: dict[str, JsonValue] | None
    sources: dict[str, JsonValue] | None
    last_sync: LastSync | None


class ReleaseFacts(StrictModel):
    repository: str
    tag_prefix: str
    checked_at: str | None
    newest: str | None


class Health(Envelope):
    status: Literal["ok", "degraded"]
    version: str
    ready: bool
    database: DatabaseFacts
    data: DataFacts
    release: ReleaseFacts


class BundleFile(StrictModel):
    file: str
    sha256: str
    rows: int | None


class BundleFacts(StrictModel):
    tag: str
    manifest_sha256: str
    generated_at: str
    lake_digest: str
    files: list[BundleFile]
    absent_columns: dict[str, list[str]]


class Limits(StrictModel):
    page_size_max: int
    sbom_upload_max_bytes: int
    lookups_per_day: int
    matches_per_day: int
    sync_calls_per_minute: int
    storage_ceiling_mb: int


class Meta(Envelope):
    version: str
    nvd_notice: str
    attribution: list[str]
    repository: str
    locks: dict[str, JsonValue]
    bundle: BundleFacts | None
    limits: Limits
    # From the loaded bundle's manifest: the lake's quarantine counts by rule, and the newest rows
    # of the fetch run ledger. Empty until a bundle is loaded.
    quarantine: list[dict[str, JsonValue]] = Field(default_factory=list)
    run_ledger: list[dict[str, JsonValue]] = Field(default_factory=list)
