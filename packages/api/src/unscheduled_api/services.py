"""The services the API routes and the CLI commands share, built once per process.

`unsched cve CVE-2021-44228` and GET /v1/cves/CVE-2021-44228 call the same function with the same
connection factory, so an answer on the command line and an answer from the API cannot differ by
code; tests/cli asserts that they do not differ by output either.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime

import sqlalchemy as sa
import structlog
from unscheduled_core.statements import STATEMENT

from unscheduled_api.budget import LOOKUPS, MATCHES, Budget
from unscheduled_api.db import make_engine
from unscheduled_api.facts import FactsCache
from unscheduled_api.legacy import AdapterWriter, LegacyWriter
from unscheduled_api.matching import Matcher, OsvApiAdvisories, PackageMatcher
from unscheduled_api.problems import ProblemError
from unscheduled_api.releases import GitHubReleases
from unscheduled_api.settings import DATABASE_VARIABLES, Settings
from unscheduled_api.sync import Sync
from unscheduled_api.versions import VersionCache

log = structlog.get_logger("unscheduled.services")


NO_DATABASE = "no database is configured: none of " + ", ".join(DATABASE_VARIABLES) + " is set"


def database_problem(err: BaseException) -> ProblemError:
    cause = err.orig if isinstance(err, sa.exc.DBAPIError) and err.orig is not None else err
    return ProblemError("database-unavailable", f"the database did not answer ({type(cause).__name__})")


@dataclass
class Services:
    settings: Settings
    engine: sa.Engine | None
    releases: GitHubReleases
    matcher: Matcher
    legacy: LegacyWriter
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    versions: VersionCache = field(init=False)
    facts: FactsCache = field(init=False)
    budget: Budget | None = field(init=False)
    statement: str = STATEMENT

    def __post_init__(self) -> None:
        self.versions = VersionCache(self.engine, self.settings.schema)
        self.facts = FactsCache(self.engine, self.settings)
        limits = {
            LOOKUPS: self.settings.budgets.lookups_per_day,
            MATCHES: self.settings.budgets.matches_per_day,
        }
        self.budget = (
            Budget(self.engine, self.settings.schema, limits, clock=self.clock)
            if self.engine is not None
            else None
        )

    @classmethod
    def build(
        cls,
        settings: Settings | None = None,
        *,
        engine: sa.Engine | None = None,
        releases: GitHubReleases | None = None,
        matcher: Matcher | None = None,
        legacy: LegacyWriter | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> Services:
        settings = settings or Settings.from_env()
        if engine is None and settings.database_url is not None:
            engine = make_engine(settings.database_url, settings.schema)
        return cls(
            settings=settings,
            engine=engine,
            releases=releases or GitHubReleases(),
            matcher=matcher or PackageMatcher(OsvApiAdvisories()),
            legacy=legacy or AdapterWriter(),
            clock=clock or (lambda: datetime.now(UTC)),
        )

    def label(self) -> str:
        return self.versions.label()

    @contextmanager
    def connection(self) -> Iterator[sa.Connection]:
        if self.engine is None:
            raise ProblemError("database-unavailable", NO_DATABASE)
        try:
            conn = self.engine.connect()
        except sa.exc.SQLAlchemyError as err:
            raise database_problem(err) from err
        try:
            yield conn
        except (sa.exc.OperationalError, sa.exc.InterfaceError) as err:
            raise database_problem(err) from err
        finally:
            conn.close()

    def require_budget(self) -> Budget:
        if self.budget is None:
            raise ProblemError("database-unavailable", NO_DATABASE + "; the client budget is kept there")
        return self.budget

    def sync(self) -> Sync:
        if self.engine is None:
            raise ProblemError("database-unavailable", NO_DATABASE + "; the sync loads into it")

        def done() -> None:
            self.versions.invalidate()
            self.facts.invalidate()

        return Sync(self.engine, self.settings, self.releases, clock=self.clock, on_done=done)

    def dispose(self) -> None:
        if self.engine is not None:
            self.engine.dispose()
