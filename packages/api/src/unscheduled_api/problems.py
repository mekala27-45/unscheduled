"""Typed problem documents (RFC 9457) for every error the API returns.

A client never parses an error string. Every failure has a type URI that names it, a fixed title and
status, a detail written for the person reading it, and the statement and data version that every
response carries. The type URI points at the section of docs/SPEC.md that explains the problem and
what to do about it, so the documentation and the error cannot drift apart without a test noticing
(tests/api/test_problems.py reads the anchors back from the spec).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from pydantic import JsonValue
from unscheduled_core.model import StrictModel

PROBLEM_BASE = "https://github.com/mekala27-45/unscheduled/blob/main/docs/SPEC.md#problem-"
MEDIA_TYPE = "application/problem+json"


@dataclass(frozen=True)
class Kind:
    slug: str
    title: str
    status: int

    @property
    def type_uri(self) -> str:
        return PROBLEM_BASE + self.slug


KINDS: dict[str, Kind] = {
    k.slug: k
    for k in (
        Kind("not-found", "The resource does not exist", 404),
        Kind("method-not-allowed", "The method is not allowed on this path", 405),
        Kind("invalid-request", "The request did not validate", 422),
        Kind("invalid-cursor", "The cursor is not one this listing issued", 400),
        Kind("malformed-body", "The body is not JSON", 400),
        Kind("unsupported-media-type", "The body is not a JSON SBOM", 415),
        Kind("unsupported-sbom", "The document is neither CycloneDX nor SPDX JSON", 422),
        Kind("payload-too-large", "The upload is over the size limit", 413),
        Kind("budget-exhausted", "This client has used its daily budget", 429),
        Kind("sync-rate-limited", "The sync was called too often", 429),
        Kind("sync-busy", "Another sync call holds the lock", 409),
        Kind("storage-ceiling", "Loading more would pass the storage ceiling", 507),
        Kind("bundle-rejected", "The serving bundle failed a check and nothing was loaded from it", 502),
        Kind("upstream-unavailable", "A public source the API reads did not answer", 503),
        Kind("database-unavailable", "The database is not configured or did not answer", 503),
        Kind("data-not-loaded", "No serving bundle has been loaded yet", 503),
        Kind("matcher-unavailable", "The matcher is not available in this deployment", 503),
        Kind("legacy-unavailable", "The legacy report adapter is not available in this deployment", 503),
        Kind("internal", "The server failed while answering", 500),
    )
}


class FieldError(StrictModel):
    location: str
    message: str


class Problem(StrictModel):
    type: str
    title: str
    status: int
    detail: str
    instance: str | None = None
    errors: list[FieldError] | None = None
    retry_after_s: int | None = None
    context: dict[str, JsonValue] | None = None
    statement: str
    data_version: str


class ProblemError(Exception):
    """Raised anywhere below a route; the app turns it into a problem document."""

    def __init__(
        self,
        slug: str,
        detail: str,
        *,
        retry_after_s: int | None = None,
        errors: list[FieldError] | None = None,
        context: Mapping[str, JsonValue] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        if slug not in KINDS:
            raise KeyError(f"no problem type named {slug!r}")
        super().__init__(f"{slug}: {detail}")
        self.kind = KINDS[slug]
        self.detail = detail
        self.retry_after_s = retry_after_s
        self.errors = errors
        self.context = dict(context) if context is not None else None
        self.headers = dict(headers or {})
        if retry_after_s is not None:
            self.headers.setdefault("Retry-After", str(max(int(retry_after_s), 1)))

    def document(self, *, instance: str | None, statement: str, data_version: str) -> Problem:
        return Problem(
            type=self.kind.type_uri,
            title=self.kind.title,
            status=self.kind.status,
            detail=self.detail,
            instance=instance,
            errors=self.errors,
            retry_after_s=self.retry_after_s,
            context=self.context,
            statement=statement,
            data_version=data_version,
        )
