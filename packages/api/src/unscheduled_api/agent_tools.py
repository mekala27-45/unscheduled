"""The MCP tools over the API's services: the same functions the routes call, so a tool and its route
cannot answer differently by code.

Over HTTP every call counts against the caller's daily budget as a route does, and start_triage also
against the serving budgets of the triage route, past which the floor drafts. Over stdio (unsched
mcp, on a laptop) nothing is counted, as the command line counts nothing. A problem the services
raise reaches the client as a refusal with its kind and detail.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import date
from typing import Any, TypeVar

from unscheduled_mcp import server as mcp_server
from unscheduled_mcp import tools

from unscheduled_api import VERSION, cves, exposure
from unscheduled_api.budget import LOOKUPS, TRIAGE, client_address
from unscheduled_api.problems import ProblemError
from unscheduled_api.services import Services, database_errors

T = TypeVar("T")
SEARCH_RESULTS = 10


@contextmanager
def refused() -> Iterator[None]:
    """A problem the services raise, as the refusal the dispatcher hands back."""
    try:
        with database_errors():
            yield
    except ProblemError as err:
        raise tools.ToolError(err.kind.slug, str(err).split(": ", 1)[-1]) from err


class ServicesBackend:
    def __init__(self, svc: Services, address: str | None) -> None:
        self.svc = svc
        self.address = address

    def _counted(self, call: Callable[[], T]) -> T:
        with refused():
            if self.address is not None:
                self.svc.require_budget().charge(self.address, LOOKUPS)
            return call()

    def lookup_cve(self, cve_id: str, as_of: date | None) -> dict[str, Any]:
        def call() -> dict[str, Any]:
            with self.svc.connection() as conn:
                record = cves.get_cve(
                    conn, cve_id, as_of, statement=self.svc.statement, data_version=self.svc.label()
                )
            return record.model_dump(mode="json")

        return self._counted(call)

    def search_cves(self, filters: dict[str, Any], limit: int) -> dict[str, Any]:
        def call() -> dict[str, Any]:
            with self.svc.connection() as conn:
                page = cves.list_cves(
                    conn,
                    cves.CveFilters(**filters),
                    cursor=None,
                    limit=limit,
                    statement=self.svc.statement,
                    data_version=self.svc.label(),
                )
            return page.model_dump(mode="json")

        return self._counted(call)

    def read_exposure(self, product_id: str, as_of: date | None) -> dict[str, Any]:
        def call() -> dict[str, Any]:
            with self.svc.connection() as conn:
                found = exposure.exposure(
                    conn,
                    product_id,
                    as_of.isoformat() if as_of else None,
                    statement=self.svc.statement,
                    data_version=self.svc.label(),
                )
            return found.model_dump(mode="json")

        return self._counted(call)

    def search(self, query: str, as_of: date) -> list[dict[str, Any]]:
        return self._counted(lambda: self.svc.triage().search(query, as_of, SEARCH_RESULTS))

    def start_triage(self, cve_id: str, as_of: date | None) -> dict[str, Any]:
        def call() -> dict[str, Any]:
            from unscheduled_api import triage

            reason = None
            if self.address is not None:
                _client, mine, everyone = self.svc.require_budget().tally(self.address, TRIAGE)
                reason = triage.floor_reason(mine, everyone, triage.serving(self.svc.settings.root))
            return self.svc.triage().start(cve_id, as_of, reason=reason)

        return self._counted(call)

    def read_run(self, run_id: str) -> dict[str, Any]:
        return self._counted(lambda: self.svc.triage().read(run_id))


def build(svc: Services, *, counted: bool) -> Any:
    """The MCP server over these services; counted, each HTTP caller's calls count against its budget."""

    def backend_for(request: Any) -> tools.Backend:
        address = (
            client_address(request)
            if counted and request is not None and hasattr(request, "headers")
            else None
        )
        if counted and address is None:
            address = "unknown"
        return ServicesBackend(svc, address)

    return mcp_server.build(backend_for, VERSION)
