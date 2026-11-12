"""The API as a FastAPI app. Every route of section 12, the problem documents, CORS and the budget.

    GET  /health                     database facts, data freshness, the release, the version
    GET  /v1/meta                    lock digests, the bundle, the statement, the NVD notice, attribution
    GET  /v1/cves/{id}               every field with its source and known_from; ?as_of= for a past day
    GET  /v1/cves                    filtered, newest first, cursor pages of at most 100
    GET  /v1/cves/{id}/timeline      the ruler events in time order
    GET  /v1/backlog                 the Q1 to Q6 values from the manifest
    GET  /v1/products                the stand ins with their pins
    GET  /v1/products/{id}/exposure  findings on a snapshot date, each CVE as known that day
    POST /v1/match                   a CycloneDX or SPDX JSON SBOM up to the upload limit
    GET  /v1/legacy/report.csv       the customer's legacy CSV, written by the strangler adapter
    POST /internal/sync              one bounded step of loading the newest serving release
    GET  /internal/sync              the same handler, for the Vercel cron, which sends GET

/health and /v1/meta are free; every /v1 data route counts against the client's daily budget.
"""

from __future__ import annotations

import re
import time
import traceback
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime
from pathlib import Path as FilePath
from typing import Annotated, Any

import sqlalchemy as sa
import structlog
from fastapi import Depends, FastAPI, Path, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BeforeValidator, JsonValue
from starlette.exceptions import HTTPException as StarletteHTTPException
from unscheduled_core.hashing import sha256_file
from unscheduled_core.statements import GHSA_ATTRIBUTION, NVD_NOTICE

from unscheduled_api import VERSION, cves, exposure, legacy, logs, matching, migrate, openapi
from unscheduled_api.budget import LOOKUPS, MATCHES, client_address
from unscheduled_api.problems import MEDIA_TYPE, FieldError, ProblemError
from unscheduled_api.releases import OWNER, REPO, TAG_PREFIX
from unscheduled_api.schemas import (
    Backlog,
    BundleFacts,
    BundleFile,
    CvePage,
    CveRecord,
    DataFacts,
    Exposure,
    Health,
    Limits,
    MatchCounts,
    MatchResponse,
    Meta,
    Products,
    ReleaseFacts,
    SbomSummary,
    SyncChunk,
    SyncResponse,
    Timeline,
)
from unscheduled_api.services import Services, database_problem
from unscheduled_api.settings import Settings
from unscheduled_api.sync import CALLS_PER_MINUTE

log = structlog.get_logger("unscheduled.api")

UPLOAD_TYPES = frozenset({"application/json", "application/vnd.cyclonedx+json", "application/spdx+json"})
PRODUCT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$"
AS_OF_PATTERN = r"^(pin|today|[0-9]{4}-[0-9]{2}-[0-9]{2})$"
STORED = (
    "Only the sha256 of the document, its size, the component and finding counts, the time taken and "
    "a salted hash of the client were stored. The document itself was not."
)
SBOM_SCHEMA: dict[str, Any] = {
    "anyOf": [
        {
            "title": "CycloneDX JSON",
            "type": "object",
            "required": ["bomFormat", "specVersion"],
            "properties": {
                "bomFormat": {"const": "CycloneDX"},
                "specVersion": {"type": "string"},
                "components": {"type": "array", "items": {"type": "object"}},
            },
        },
        {
            "title": "SPDX 2 JSON",
            "type": "object",
            "required": ["spdxVersion"],
            "properties": {
                "spdxVersion": {"type": "string", "pattern": "^SPDX-2\\.[0-9]+$"},
                "packages": {"type": "array", "items": {"type": "object"}},
            },
        },
    ]
}
DATA_ERRORS = (404, 422, 429, 500, 503)
ISO_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


def _iso_date(value: Any) -> Any:
    """A day as YYYY-MM-DD and nothing else: no Unix times, no timestamps, which pydantic would accept."""
    if isinstance(value, date):
        return value
    if not isinstance(value, str) or not ISO_DATE.match(value):
        raise ValueError("a date is written YYYY-MM-DD")
    return value


IsoDate = Annotated[date, BeforeValidator(_iso_date)]


def local_locks(root: FilePath) -> dict[str, JsonValue]:
    """The lock files committed in data/locks, by source, with the digest of each."""
    folder = root / "data" / "locks"
    if not folder.is_dir():
        return {}
    return {
        path.name.removesuffix(".lock.json"): {"lock_sha256": sha256_file(path)}
        for path in sorted(folder.glob("*.lock.json"))
    }


def create_app(services: Services | None = None, *, settings: Settings | None = None) -> FastAPI:
    logs.configure()
    svc = services or Services.build(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if svc.engine is not None and svc.settings.migrate_on_start:
            failed = await run_in_threadpool(migrate.upgrade, svc.settings)
            if failed is None and svc.budget is not None:
                try:
                    await run_in_threadpool(svc.budget.salt)
                except sa.exc.SQLAlchemyError as err:
                    log.error("the client salt could not be made", error=type(err).__name__)
        yield
        svc.dispose()

    app = FastAPI(
        title="unscheduled",
        version=VERSION,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
        swagger_ui_parameters={"defaultModelsExpandDepth": 0},
    )
    app.state.services = svc
    openapi.install(app)

    # Problems ------------------------------------------------------------------------------------

    def problem(request: Request, err: ProblemError) -> JSONResponse:
        doc = err.document(instance=request.url.path, statement=svc.statement, data_version=svc.label())
        return JSONResponse(
            doc.model_dump(mode="json", exclude_none=True),
            status_code=err.kind.status,
            media_type=MEDIA_TYPE,
            headers=err.headers,
        )

    async def on_problem(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, ProblemError)
        return await run_in_threadpool(problem, request, exc)

    async def on_invalid(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, RequestValidationError)
        errors = [
            FieldError(location=".".join(str(p) for p in e.get("loc", ())), message=str(e.get("msg", "")))
            for e in exc.errors()
        ][:20]
        err = ProblemError("invalid-request", "one or more parameters did not validate", errors=errors)
        return await run_in_threadpool(problem, request, err)

    async def on_http(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, StarletteHTTPException)
        status = exc.status_code
        if status == 404:
            err = ProblemError("not-found", f"no route answers {request.url.path}")
        elif status == 405:
            # Two routes can share a path (the sync answers GET and POST), so Allow is the union of
            # every route that matches the path, not only the first one the router tried.
            allowed = sorted(
                {
                    method
                    for route in app.routes
                    if isinstance(route, APIRoute) and route.path_regex.match(request.url.path)
                    for method in route.methods or ()
                }
            )
            err = ProblemError(
                "method-not-allowed",
                f"{request.method} is not allowed on {request.url.path}",
                headers={"Allow": ", ".join(allowed)},
            )
        elif status == 413:
            err = ProblemError("payload-too-large", str(exc.detail))
        elif status == 415:
            err = ProblemError("unsupported-media-type", str(exc.detail))
        elif 400 <= status < 500:
            err = ProblemError("invalid-request", str(exc.detail))
        else:
            err = ProblemError("internal", "the server failed while answering")
        return await run_in_threadpool(problem, request, err)

    async def on_error(request: Request, exc: Exception) -> Response:
        if isinstance(exc, sa.exc.OperationalError | sa.exc.InterfaceError):
            return await run_in_threadpool(problem, request, database_problem(exc))
        frames = [f"{FilePath(f.filename).name}:{f.lineno}" for f in traceback.extract_tb(exc.__traceback__)]
        log.error("unhandled", error=type(exc).__name__, path=request.url.path, frames=frames[-8:])
        err = ProblemError("internal", "the server failed while answering; the error was logged by its type")
        return await run_in_threadpool(problem, request, err)

    app.add_exception_handler(ProblemError, on_problem)
    app.add_exception_handler(RequestValidationError, on_invalid)
    app.add_exception_handler(StarletteHTTPException, on_http)
    app.add_exception_handler(Exception, on_error)

    # Every response: the data version header and one log line ------------------------------------

    @app.middleware("http")
    async def stamp(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        started = time.perf_counter()
        response = await call_next(request)
        response.headers.setdefault("X-Data-Version", await run_in_threadpool(svc.label))
        route = request.scope.get("route")
        client = getattr(request.state, "client", None)
        log.info(
            "request",
            method=request.method,
            route=getattr(route, "path", None) or "unmatched",
            status=response.status_code,
            ms=round((time.perf_counter() - started) * 1000.0, 1),
            client=client[:8] if isinstance(client, str) else None,
        )
        return response

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(svc.settings.cors_origins),
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Accept"],
        expose_headers=["X-Data-Version", "X-Budget-Limit", "X-Budget-Remaining", "Retry-After"],
        max_age=600,
    )

    # Dependencies --------------------------------------------------------------------------------

    def charge_lookup(request: Request, response: Response) -> None:
        budget = svc.require_budget()
        try:
            client, used, limit = budget.charge(client_address(request), LOOKUPS)
        except sa.exc.SQLAlchemyError as err:
            raise database_problem(err) from err
        request.state.client = client
        headers = {"X-Budget-Limit": str(limit), "X-Budget-Remaining": str(max(limit - used, 0))}
        request.state.budget_headers = headers
        response.headers.update(headers)

    def require_data() -> None:
        state = svc.versions.state()
        if svc.engine is None or state is None:
            raise ProblemError("database-unavailable", "the database is not configured or did not answer")
        if state.loaded is None:
            raise ProblemError(
                "data-not-loaded",
                "no serving bundle has been loaded yet; the sync loads the newest release",
                context={"loading": (state.loading or {}).get("target", {}).get("tag")},
            )

    looked_up = [Depends(charge_lookup), Depends(require_data)]

    # Service -------------------------------------------------------------------------------------

    @app.get("/health", response_model=Health, tags=["service"], responses=openapi.problem_responses(500))
    def health() -> Health:
        facts, last = svc.facts.get()
        state = svc.versions.state()
        loaded = (state.loaded if state else None) or {}
        loading = (state.loading if state else None) or {}
        check = (state.release_check if state else None) or {}
        newest = check.get("newest") or {}
        data = DataFacts(
            data_version=svc.label(),
            tag=loaded.get("tag"),
            generated_at=loaded.get("generated_at"),
            loaded_at=loaded.get("loaded_at"),
            lake_digest=loaded.get("lake_digest"),
            loading=(loading.get("target") or {}).get("tag"),
            counts=loaded.get("counts"),
            freshness=loaded.get("freshness"),
            sources=loaded.get("sources"),
            last_sync=last,
        )
        degraded = facts.configured and (not facts.reachable or facts.migration is None)
        return Health(
            statement=svc.statement,
            data_version=data.data_version,
            status="degraded" if degraded else "ok",
            version=VERSION,
            ready=bool(facts.reachable and loaded),
            database=facts,
            data=data,
            release=ReleaseFacts(
                repository=f"{OWNER}/{REPO}",
                tag_prefix=TAG_PREFIX,
                checked_at=check.get("checked_at"),
                newest=newest.get("tag"),
            ),
        )

    @app.get("/v1/meta", response_model=Meta, tags=["service"], responses=openapi.problem_responses(500))
    def meta() -> Meta:
        state = svc.versions.state()
        loaded = state.loaded if state else None
        bundle = None
        locks: dict[str, JsonValue] = local_locks(svc.settings.root)
        quarantine: list[dict[str, JsonValue]] = []
        run_ledger: list[dict[str, JsonValue]] = []
        if loaded:
            sources = loaded.get("sources") or {}
            rules = (sources.get("quarantine") or {}).get("rules") if isinstance(sources, dict) else None
            quarantine = [r for r in rules or [] if isinstance(r, dict)]
            ledger = sources.get("ledger_recent") if isinstance(sources, dict) else None
            run_ledger = [r for r in ledger or [] if isinstance(r, dict)]
            bundle = BundleFacts(
                tag=loaded["tag"],
                manifest_sha256=loaded["manifest_sha256"],
                generated_at=loaded["generated_at"],
                lake_digest=loaded["lake_digest"],
                files=[
                    BundleFile(file=f["file"], sha256=f["sha256"], rows=f.get("rows"))
                    for f in loaded["files"]
                ],
                absent_columns=loaded.get("absent_columns") or {},
            )
            if loaded.get("locks"):
                locks = loaded["locks"]
        budgets = svc.settings.budgets
        return Meta(
            statement=svc.statement,
            data_version=svc.label(),
            version=VERSION,
            nvd_notice=NVD_NOTICE,
            attribution=[GHSA_ATTRIBUTION],
            repository=f"{OWNER}/{REPO}",
            locks=locks,
            bundle=bundle,
            quarantine=quarantine,
            run_ledger=run_ledger,
            limits=Limits(
                page_size_max=cves.PAGE_MAX,
                sbom_upload_max_bytes=budgets.sbom_upload_max_bytes,
                lookups_per_day=budgets.lookups_per_day,
                matches_per_day=budgets.matches_per_day,
                sync_calls_per_minute=CALLS_PER_MINUTE,
                storage_ceiling_mb=budgets.storage_ceiling_mb,
            ),
        )

    # CVEs ----------------------------------------------------------------------------------------

    @app.get(
        "/v1/cves/{cve_id}",
        response_model=CveRecord,
        tags=["cves"],
        dependencies=looked_up,
        responses=openapi.problem_responses(*DATA_ERRORS),
    )
    def get_cve(
        cve_id: Annotated[str, Path(pattern=cves.CVE_ID_PATTERN, examples=["CVE-2021-44228"])],
        as_of: Annotated[
            IsoDate | None,
            Query(description="the state at the end of this day (UTC), from facts known by then"),
        ] = None,
    ) -> CveRecord:
        with svc.connection() as conn:
            return cves.get_cve(conn, cve_id, as_of, statement=svc.statement, data_version=svc.label())

    @app.get(
        "/v1/cves",
        response_model=CvePage,
        tags=["cves"],
        dependencies=looked_up,
        responses=openapi.problem_responses(400, *DATA_ERRORS),
    )
    def list_cves(
        published_from: Annotated[IsoDate | None, Query(description="published on or after this day")] = None,
        published_to: Annotated[IsoDate | None, Query(description="published on or before this day")] = None,
        nvd_status: Annotated[str | None, Query(max_length=60, pattern=cves.TEXT_PATTERN)] = None,
        kev: Annotated[bool | None, Query(description="listed in CISA KEV")] = None,
        filer: Annotated[str | None, Query(max_length=120, pattern=cves.TEXT_PATTERN)] = None,
        filer_type: Annotated[str | None, Query(max_length=60, pattern=cves.TEXT_PATTERN)] = None,
        cwe: Annotated[str | None, Query(pattern=cves.CWE_PATTERN, examples=["CWE-79"])] = None,
        has_filer_score: Annotated[
            bool | None, Query(description="the filer gave a CVSS 3.1 or 4.0 score")
        ] = None,
        kev_added_from: Annotated[
            IsoDate | None, Query(description="added to CISA KEV on or after this day")
        ] = None,
        analyzed_from: Annotated[
            IsoDate | None, Query(description="the NVD status is Analyzed, since this day or later")
        ] = None,
        cursor: Annotated[str | None, Query(max_length=512, pattern=r"^[A-Za-z0-9_-]+$")] = None,
        limit: Annotated[int, Query(ge=1, le=cves.PAGE_MAX)] = cves.PAGE_DEFAULT,
    ) -> CvePage:
        filters = cves.CveFilters(
            published_from=published_from,
            published_to=published_to,
            nvd_status=nvd_status,
            kev=kev,
            filer=filer,
            filer_type=filer_type,
            cwe=cves.normalize_cwe(cwe) if cwe else None,
            has_filer_score=has_filer_score,
            kev_added_from=kev_added_from,
            analyzed_from=analyzed_from,
        )
        with svc.connection() as conn:
            return cves.list_cves(
                conn, filters, cursor=cursor, limit=limit, statement=svc.statement, data_version=svc.label()
            )

    @app.get(
        "/v1/cves/{cve_id}/timeline",
        response_model=Timeline,
        tags=["cves"],
        dependencies=looked_up,
        responses=openapi.problem_responses(*DATA_ERRORS),
    )
    def get_timeline(
        cve_id: Annotated[str, Path(pattern=cves.CVE_ID_PATTERN, examples=["CVE-2021-44228"])],
    ) -> Timeline:
        with svc.connection() as conn:
            return cves.timeline(conn, cve_id, statement=svc.statement, data_version=svc.label())

    # The backlog, the products and the exposure --------------------------------------------------

    @app.get(
        "/v1/backlog",
        response_model=Backlog,
        tags=["backlog"],
        dependencies=looked_up,
        responses=openapi.problem_responses(429, 500, 503),
    )
    def get_backlog() -> Backlog:
        with svc.connection() as conn:
            return exposure.backlog(conn, statement=svc.statement, data_version=svc.label())

    @app.get(
        "/v1/products",
        response_model=Products,
        tags=["exposure"],
        dependencies=looked_up,
        responses=openapi.problem_responses(429, 500, 503),
    )
    def get_products() -> Products:
        with svc.connection() as conn:
            return exposure.list_products(conn, statement=svc.statement, data_version=svc.label())

    @app.get(
        "/v1/products/{product_id}/exposure",
        response_model=Exposure,
        tags=["exposure"],
        dependencies=looked_up,
        responses=openapi.problem_responses(*DATA_ERRORS),
    )
    def get_exposure(
        product_id: Annotated[str, Path(pattern=PRODUCT_PATTERN, examples=["go-edge-service"])],
        as_of: Annotated[
            str | None,
            Query(
                pattern=AS_OF_PATTERN,
                description="pin, today (the default) or a date: the snapshot on or before it",
            ),
        ] = None,
    ) -> Exposure:
        with svc.connection() as conn:
            return exposure.exposure(
                conn, product_id, as_of, statement=svc.statement, data_version=svc.label()
            )

    # Matching ------------------------------------------------------------------------------------

    @app.post(
        "/v1/match",
        response_model=MatchResponse,
        tags=["match"],
        responses=openapi.problem_responses(400, 413, 415, 422, 429, 500, 503),
        openapi_extra={
            "requestBody": {
                "required": True,
                "description": "a CycloneDX JSON or SPDX 2 JSON document, up to the upload limit in /v1/meta",
                "content": {media: {"schema": SBOM_SCHEMA} for media in sorted(UPLOAD_TYPES)},
            }
        },
    )
    async def match_sbom(request: Request, response: Response) -> MatchResponse:
        limit = svc.settings.budgets.sbom_upload_max_bytes
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            raise ProblemError(
                "payload-too-large", f"the upload limit is {limit} bytes; this body declares {declared}"
            )
        media = request.headers.get("content-type", "application/json").split(";")[0].strip().lower()
        if media not in UPLOAD_TYPES:
            raise ProblemError(
                "unsupported-media-type",
                f"send the SBOM as one of {', '.join(sorted(UPLOAD_TYPES))}, not {media or 'no type'}",
            )
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > limit:
                raise ProblemError("payload-too-large", f"the upload limit is {limit} bytes")
        budget = svc.require_budget()
        try:
            client, used, allowed = await run_in_threadpool(budget.charge, client_address(request), MATCHES)
        except sa.exc.SQLAlchemyError as err:
            raise database_problem(err) from err
        request.state.client = client
        response.headers.update(
            {"X-Budget-Limit": str(allowed), "X-Budget-Remaining": str(max(allowed - used, 0))}
        )
        sbom = matching.parse_sbom(bytes(body))
        at = datetime.now(UTC)
        started = time.perf_counter()
        run: matching.MatchRun | None = None
        status = "ok"
        try:
            run = await run_in_threadpool(matching.run_match, svc.matcher, sbom)
        except ProblemError as err:
            status = err.kind.slug
            raise
        except Exception:
            status = "internal"
            raise
        finally:
            elapsed = run.duration_ms if run else round((time.perf_counter() - started) * 1000.0, 1)

            def write() -> None:
                with svc.connection() as conn:
                    matching.log_match(
                        conn, at=at, sbom=sbom, client=client, status=status, duration_ms=elapsed, run=run
                    )
                    conn.commit()

            await run_in_threadpool(write)
        assert run is not None
        result = run.result
        return MatchResponse(
            statement=svc.statement,
            data_version=svc.label(),
            sbom=SbomSummary(
                sha256=sbom.sha256,
                bytes=sbom.size,
                format=sbom.format,
                spec_version=sbom.spec_version,
                components=len(sbom.components),
                with_purl=sbom.with_purl,
                without_purl=sbom.without_purl,
            ),
            engine=result.engine,
            as_of=run.as_of,
            findings=result.findings,
            counts=MatchCounts(
                findings=len(result.findings),
                distinct_cves=result.distinct_cves,
                components_matched=result.components_matched,
                advisories_read=result.advisories_read,
            ),
            duration_ms=run.duration_ms,
            stored=STORED,
        )

    # The legacy report ---------------------------------------------------------------------------

    @app.get(
        "/v1/legacy/report.csv",
        response_class=Response,
        tags=["legacy"],
        dependencies=looked_up,
        responses={
            200: {
                "description": "the legacy CSV, same columns, order, types and date format as the 2019 job",
                "content": {"text/csv": {"schema": {"type": "string"}}},
            },
            **openapi.problem_responses(429, 500, 503),
        },
    )
    def legacy_report(request: Request) -> Response:
        with svc.connection() as conn:
            text = legacy.report_csv(conn, svc.legacy)
        headers = {
            "Content-Disposition": 'attachment; filename="report.csv"',
            "X-Unscheduled-Statement": svc.statement,
            **getattr(request.state, "budget_headers", {}),
        }
        return Response(text, media_type="text/csv; charset=utf-8", headers=headers)

    # The sync ------------------------------------------------------------------------------------

    sync_doc = openapi.problem_responses(409, 429, 500, 502, 503, 507)
    sync_text = (
        "One bounded step of loading the newest serving release of "
        f"{OWNER}/{REPO} into the database. It takes no input. Call it until status is done or current; "
        "status more means call again. GET serves the Vercel cron, which only sends GET."
    )

    def run_sync() -> SyncResponse:
        outcome = svc.sync().run_once()
        chunk = outcome.chunk
        return SyncResponse(
            statement=svc.statement,
            data_version=svc.label(),
            status=outcome.status,
            detail=outcome.detail,
            target=outcome.target,
            step=outcome.step,
            step_index=outcome.step_index,
            steps=outcome.steps,
            chunk=SyncChunk(
                table=chunk.table,
                offset=chunk.offset,
                rows_in=chunk.rows_in,
                rows_changed=chunk.rows_changed,
                rows_total=chunk.rows_total,
            )
            if chunk
            else None,
            chunks_done=outcome.chunks_done,
            chunks_total=outcome.chunks_total,
            storage_bytes=outcome.storage_bytes,
            storage_ceiling_bytes=outcome.storage_ceiling_bytes,
            checked_release=outcome.checked_release,
        )

    @app.post(
        "/internal/sync",
        response_model=SyncResponse,
        tags=["sync"],
        operation_id="sync_post",
        summary="Load the next step of the newest serving release",
        description=sync_text,
        responses=sync_doc,
    )
    def sync_post() -> SyncResponse:
        return run_sync()

    @app.get(
        "/internal/sync",
        response_model=SyncResponse,
        tags=["sync"],
        operation_id="sync_get",
        summary="Load the next step of the newest serving release (the cron)",
        description=sync_text,
        responses=sync_doc,
    )
    def sync_get() -> SyncResponse:
        return run_sync()

    return app
