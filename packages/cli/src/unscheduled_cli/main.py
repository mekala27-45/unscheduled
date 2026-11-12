"""unsched: the command line over the same services as the API.

    unsched probe [args]               every host and source probed (scripts/probe_hosts.py)
    unsched fetch SOURCE... [args]     sources fetched and locked (scripts/fetch.py)
    unsched build [args]               the lake from bronze to gold (scripts/build_lake.py)
    unsched render [--check]           the documents from the manifest, the claim gate
    unsched sync [--until-done]        one step, or every step, of loading the newest serving release
    unsched cve ID [--as-of DATE]      as GET /v1/cves/{id}
    unsched cves [filters]             as GET /v1/cves
    unsched timeline ID                as GET /v1/cves/{id}/timeline
    unsched backlog                    as GET /v1/backlog
    unsched products                   as GET /v1/products
    unsched exposure ID [--as-of]      as GET /v1/products/{id}/exposure
    unsched match SBOM                 as POST /v1/match
    unsched legacy-report [--out FILE] as GET /v1/legacy/report.csv
    unsched serve [--host --port]      the API itself, under uvicorn

The data commands print the same JSON the API answers, built by the same functions from the same
database (the variables the API reads: DATABASE_URL_UNPOOLED, DATABASE_URL or POSTGRES_URL).
A problem prints the same problem document to stderr and exits 1. tests/cli holds the two to the
same answers. Two differences are deliberate: `match` reads a local file of any size, since the
upload limit protects the public service and not a laptop, and `match --advisories FILE` matches
against a local copy of OSV records instead of api.osv.dev.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import BaseModel
from unscheduled_api import cves as cve_service
from unscheduled_api import exposure as exposure_service
from unscheduled_api import legacy as legacy_service
from unscheduled_api import matching
from unscheduled_api.problems import MEDIA_TYPE, ProblemError
from unscheduled_api.schemas import MatchCounts, MatchResponse, SbomSummary, SyncChunk, SyncResponse
from unscheduled_api.services import Services
from unscheduled_core import paths

ServicesFactory = Callable[[], Services]
STORED_LOCALLY = "Nothing was stored: the command line matches locally and keeps no log."
PASS_THROUGH = {"allow_extra_args": True, "ignore_unknown_options": True}


def _print(payload: Any) -> None:
    typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))


def _model(model: BaseModel) -> None:
    _print(model.model_dump(mode="json"))


def _problem(err: ProblemError, services: Services, instance: str) -> None:
    doc = err.document(instance=instance, statement=services.statement, data_version=services.label())
    typer.echo(
        json.dumps(doc.model_dump(mode="json", exclude_none=True), indent=2, ensure_ascii=False), err=True
    )
    typer.echo(f"({MEDIA_TYPE}, status {err.kind.status})", err=True)


def _script(name: str, args: list[str]) -> int:
    script = paths.root() / "scripts" / name
    if not script.exists():
        typer.echo(f"unsched: {script} is not in this checkout; run from the repository", err=True)
        return 2
    return subprocess.run([sys.executable, str(script), *args], cwd=paths.root(), check=False).returncode


def create_cli(factory: ServicesFactory | None = None) -> typer.Typer:
    app = typer.Typer(
        name="unsched",
        help="unscheduled: triage for the CVEs the NVD no longer analyzes, from the terminal.",
        no_args_is_help=True,
        add_completion=False,
    )
    built: dict[str, Services] = {}

    def services() -> Services:
        if "services" not in built:
            built["services"] = factory() if factory is not None else Services.build()
        return built["services"]

    def answer(instance: str, produce: Callable[[Services], BaseModel]) -> None:
        svc = services()
        try:
            result = produce(svc)
        except ProblemError as err:
            _problem(err, svc, instance)
            raise typer.Exit(1) from err
        _model(result)

    def require_data(svc: Services) -> None:
        state = svc.versions.state()
        if svc.engine is None or state is None:
            raise ProblemError("database-unavailable", "the database is not configured or did not answer")
        if state.loaded is None:
            raise ProblemError("data-not-loaded", "no serving bundle has been loaded yet; run unsched sync")

    # The pipeline: the same scripts CI runs -------------------------------------------------------

    @app.command(context_settings=PASS_THROUGH)
    def probe(ctx: typer.Context) -> None:
        """Probe every host and source the build depends on; writes results/probe.json."""
        raise typer.Exit(_script("probe_hosts.py", list(ctx.args)))

    @app.command(context_settings=PASS_THROUGH)
    def fetch(
        ctx: typer.Context, source: Annotated[list[str], typer.Argument(help="source names, or all")]
    ) -> None:
        """Fetch public sources into their locks, the run ledger and bronze."""
        raise typer.Exit(_script("fetch.py", [*source, *ctx.args]))

    @app.command(context_settings=PASS_THROUGH)
    def build(ctx: typer.Context) -> None:
        """Build the lake from bronze: the dated facts, the warehouse and the lake file."""
        raise typer.Exit(_script("build_lake.py", list(ctx.args)))

    @app.command()
    def render(check: Annotated[bool, typer.Option(help="only check that nothing drifted")] = False) -> None:
        """Assemble the manifest and render every document from it (the claim gate)."""
        code = _script("build_manifest.py", [])
        if code == 0:
            code = _script("check_published_numbers.py", [] if check else ["--write"])
        raise typer.Exit(code)

    # The sync -------------------------------------------------------------------------------------

    @app.command()
    def sync(
        until_done: Annotated[
            bool, typer.Option(help="call again until the answer is done or current")
        ] = False,
        max_calls: Annotated[int, typer.Option(min=1)] = 500,
    ) -> None:
        """One step, or every step, of loading the newest serving release into the database."""
        svc = services()
        for _ in range(max_calls if until_done else 1):
            try:
                outcome = svc.sync().run_once()
            except ProblemError as err:
                if until_done and err.kind.slug in {"sync-busy", "sync-rate-limited"}:
                    time.sleep(err.retry_after_s or 5)
                    continue
                _problem(err, svc, "unsched sync")
                raise typer.Exit(1) from err
            chunk = outcome.chunk
            response = SyncResponse(
                statement=svc.statement,
                data_version=svc.label(),
                status=outcome.status,
                detail=outcome.detail,
                target=outcome.target,
                step=outcome.step,
                step_index=outcome.step_index,
                steps=outcome.steps,
                chunk=SyncChunk(**vars(chunk)) if chunk else None,
                chunks_done=outcome.chunks_done,
                chunks_total=outcome.chunks_total,
                storage_bytes=outcome.storage_bytes,
                storage_ceiling_bytes=outcome.storage_ceiling_bytes,
                checked_release=outcome.checked_release,
            )
            typer.echo(json.dumps(response.model_dump(mode="json"), ensure_ascii=False))
            if outcome.status in {"done", "current"}:
                return
        if until_done:
            typer.echo(f"unsched: the sync did not finish in {max_calls} calls", err=True)
            raise typer.Exit(1)

    # Reading the slice ----------------------------------------------------------------------------

    @app.command()
    def cve(
        cve_id: Annotated[str, typer.Argument(help="a CVE id, CVE-YYYY-NNNN")],
        as_of: Annotated[
            str | None, typer.Option(help="the state at the end of this day, YYYY-MM-DD")
        ] = None,
    ) -> None:
        """A CVE with every field, its source and since when; with --as-of, as known that day."""

        def produce(svc: Services) -> BaseModel:
            try:
                day = date.fromisoformat(as_of) if as_of else None
            except ValueError as err:
                raise ProblemError("invalid-request", "as_of is a date, YYYY-MM-DD") from err
            require_data(svc)
            with svc.connection() as conn:
                return cve_service.get_cve(
                    conn, cve_id, day, statement=svc.statement, data_version=svc.label()
                )

        answer(f"unsched cve {cve_id}", produce)

    @app.command()
    def cves(
        published_from: Annotated[str | None, typer.Option()] = None,
        published_to: Annotated[str | None, typer.Option()] = None,
        nvd_status: Annotated[str | None, typer.Option()] = None,
        kev: Annotated[bool | None, typer.Option("--kev/--not-kev")] = None,
        filer: Annotated[str | None, typer.Option()] = None,
        filer_type: Annotated[str | None, typer.Option()] = None,
        cwe: Annotated[str | None, typer.Option()] = None,
        has_filer_score: Annotated[bool | None, typer.Option("--has-filer-score/--no-filer-score")] = None,
        cursor: Annotated[str | None, typer.Option()] = None,
        limit: Annotated[int, typer.Option(min=1, max=cve_service.PAGE_MAX)] = cve_service.PAGE_DEFAULT,
    ) -> None:
        """A page of CVEs, newest published first, filtered as the API filters them."""

        def produce(svc: Services) -> BaseModel:
            try:
                start = date.fromisoformat(published_from) if published_from else None
                end = date.fromisoformat(published_to) if published_to else None
            except ValueError as err:
                raise ProblemError("invalid-request", "published_from and published_to are dates") from err
            filters = cve_service.CveFilters(
                published_from=start,
                published_to=end,
                nvd_status=nvd_status,
                kev=kev,
                filer=filer,
                filer_type=filer_type,
                cwe=cve_service.normalize_cwe(cwe) if cwe else None,
                has_filer_score=has_filer_score,
            )
            require_data(svc)
            with svc.connection() as conn:
                return cve_service.list_cves(
                    conn,
                    filters,
                    cursor=cursor,
                    limit=limit,
                    statement=svc.statement,
                    data_version=svc.label(),
                )

        answer("unsched cves", produce)

    @app.command()
    def timeline(cve_id: Annotated[str, typer.Argument(help="a CVE id")]) -> None:
        """The ruler events of a CVE in time order."""

        def produce(svc: Services) -> BaseModel:
            require_data(svc)
            with svc.connection() as conn:
                return cve_service.timeline(conn, cve_id, statement=svc.statement, data_version=svc.label())

        answer(f"unsched timeline {cve_id}", produce)

    @app.command()
    def backlog() -> None:
        """The Q1 to Q6 values from the manifest, as the bundle carries them."""

        def produce(svc: Services) -> BaseModel:
            require_data(svc)
            with svc.connection() as conn:
                return exposure_service.backlog(conn, statement=svc.statement, data_version=svc.label())

        answer("unsched backlog", produce)

    @app.command()
    def products() -> None:
        """The stand in products with their pins."""

        def produce(svc: Services) -> BaseModel:
            require_data(svc)
            with svc.connection() as conn:
                return exposure_service.list_products(conn, statement=svc.statement, data_version=svc.label())

        answer("unsched products", produce)

    @app.command()
    def exposure(
        product_id: Annotated[str, typer.Argument(help="a stand in product id")],
        as_of: Annotated[str | None, typer.Option(help="pin, today or a date")] = None,
    ) -> None:
        """A product's findings on a snapshot date, each CVE as it was known that day."""

        def produce(svc: Services) -> BaseModel:
            require_data(svc)
            with svc.connection() as conn:
                return exposure_service.exposure(
                    conn, product_id, as_of, statement=svc.statement, data_version=svc.label()
                )

        answer(f"unsched exposure {product_id}", produce)

    @app.command()
    def match(
        sbom: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True, help="a JSON SBOM")],
        advisories: Annotated[
            Path | None,
            typer.Option(exists=True, dir_okay=False, help="a JSON list of OSV records to match against"),
        ] = None,
    ) -> None:
        """Findings for a CycloneDX or SPDX JSON SBOM, as POST /v1/match answers them."""

        def produce(svc: Services) -> BaseModel:
            matcher: matching.Matcher = svc.matcher
            if advisories is not None:
                records = json.loads(advisories.read_text(encoding="utf-8"))
                matcher = matching.PackageMatcher(matching.StaticAdvisories(records, name=advisories.name))
            parsed = matching.parse_sbom(sbom.read_bytes())
            run = matching.run_match(matcher, parsed)
            result = run.result
            return MatchResponse(
                statement=svc.statement,
                data_version=svc.label(),
                sbom=SbomSummary(
                    sha256=parsed.sha256,
                    bytes=parsed.size,
                    format=parsed.format,
                    spec_version=parsed.spec_version,
                    components=len(parsed.components),
                    with_purl=parsed.with_purl,
                    without_purl=parsed.without_purl,
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
                stored=STORED_LOCALLY,
            )

        answer(f"unsched match {sbom.name}", produce)

    @app.command("legacy-report")
    def legacy_report(
        out: Annotated[Path | None, typer.Option(help="write the CSV here instead of stdout")] = None,
    ) -> None:
        """The customer's legacy CSV, the same bytes GET /v1/legacy/report.csv serves."""
        svc = services()
        try:
            require_data(svc)
            with svc.connection() as conn:
                data = legacy_service.report_csv(conn, svc.legacy)
        except ProblemError as err:
            _problem(err, svc, "unsched legacy-report")
            raise typer.Exit(1) from err
        if out is None:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        else:
            out.write_bytes(data)
            typer.echo(f"unsched: wrote {out} ({len(data)} bytes)", err=True)

    @app.command()
    def serve(
        host: Annotated[str, typer.Option()] = "127.0.0.1",
        port: Annotated[int, typer.Option(min=1, max=65535)] = 8000,
    ) -> None:
        """Run the API locally under uvicorn, migrations first, exactly as the container does."""
        import uvicorn

        uvicorn.run("unscheduled_api.main:app", host=host, port=port, proxy_headers=True)

    return app


def main() -> None:
    create_cli()()


if __name__ == "__main__":
    main()
