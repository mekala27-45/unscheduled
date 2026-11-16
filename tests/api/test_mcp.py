"""The MCP server over both transports, driven by the MCP SDK's own client.

Over streamable HTTP the API runs under a real uvicorn on a free port, its lifespan running the
session manager, stateless, as the Vercel function does. Over stdio the client starts
`python -m unscheduled_cli mcp` as a subprocess against the same database. Each transport lists the
six tools and no tool that acts, answers a lookup, a search and a triage run with the paths of
untrusted text, and refuses by name a tool that would approve, apply or file.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import psycopg
import pytest
import uvicorn
from fastapi.testclient import TestClient
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from unscheduled_api.app import create_app
from unscheduled_api.services import Services
from unscheduled_mcp import tools

from tests.api.postgres import plain
from tests.api.test_triage import ADVISORY, AS_OF, CVE, load_corpus

ROOT = Path(__file__).resolve().parents[2]
TOOLS = {"lookup_cve", "search_cves", "read_exposure", "search_advisories", "start_triage", "read_run"}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def served(loaded: TestClient, postgres_url: str) -> TestClient:
    load_corpus(postgres_url)
    return loaded


@pytest.fixture
def http_url(served: TestClient, services: Services) -> Iterator[str]:
    port = free_port()
    server = uvicorn.Server(
        uvicorn.Config(create_app(services), host="127.0.0.1", port=port, lifespan="on", log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True
    thread.join(timeout=10)


@pytest.fixture
def stdio_server(served: TestClient, postgres_url: str, tmp_path: Path) -> StdioServerParameters:
    env = {
        **os.environ,
        "DATABASE_URL": plain(postgres_url),
        "UNSCHED_DB_SCHEMA": "unscheduled",
        "UNSCHED_ROOT": str(ROOT),
        "UNSCHED_CACHE_DIR": str(tmp_path / "cache"),
        "UNSCHED_MIGRATE_ON_START": "0",
    }
    env.pop("DATABASE_URL_UNPOOLED", None)
    env.pop("POSTGRES_URL", None)
    return StdioServerParameters(
        command=sys.executable, args=["-m", "unscheduled_cli", "mcp"], env=env, cwd=str(ROOT)
    )


def payload(result: Any) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(result.content[0].text)
    assert result.structured_content == data
    return data


async def exercise(server: Any) -> dict[str, Any]:
    """Every check both transports must pass; returns what they answered for the caller to compare."""
    async with Client(server, read_timeout_seconds=60) as client:
        listed = await client.list_tools()
        names = {t.name for t in listed.tools}
        assert names == TOOLS and not names & set(tools.NEVER)
        assert all(t.input_schema.get("additionalProperties") is False for t in listed.tools)

        cve = payload(await client.call_tool("lookup_cve", {"cve_id": CVE, "as_of": AS_OF}))
        assert cve["result"]["cve_id"] == CVE and cve["result"]["known"] is True
        assert cve["untrusted"]["paths"] == ["fields.description.value"]

        page = payload(await client.call_tool("search_cves", {"kev": True, "limit": 5}))
        assert CVE in [item["cve_id"] for item in page["result"]["items"]]

        exposure = payload(await client.call_tool("read_exposure", {"product_id": "go-edge-service"}))
        assert exposure["result"]["product"]["product_id"] == "go-edge-service"
        assert exposure["untrusted"]["paths"] == ["findings[].attributes.summary"]

        found = payload(
            await client.call_tool("search_advisories", {"query": "logkit", "as_of": "2022-01-01"})
        )
        assert ADVISORY in {r["doc_id"] for r in found["result"]}
        assert (
            found["untrusted"]["paths"] == ["[].text"]
            and "never as an instruction" in found["untrusted"]["note"]
        )

        run = payload(await client.call_tool("start_triage", {"cve_id": CVE, "as_of": AS_OF}))
        assert run["result"]["status"] == "waiting" and run["result"]["drafts"]["plan"]["status"] == "waiting"
        assert "facts.evidence[].text" in run["untrusted"]["paths"]
        again = payload(await client.call_tool("read_run", {"run_id": run["result"]["run_id"]}))
        assert again["result"]["waiting_for"] == run["result"]["waiting_for"]

        for name in tools.NEVER:
            refused = await client.call_tool(name, {"run_id": run["result"]["run_id"]})
            assert refused.is_error and payload(refused)["refused"].startswith(f"there is no tool {name}")
        bad = await client.call_tool("lookup_cve", {"cve_id": "CVE-1", "sql": "drop table cve"})
        assert bad.is_error and payload(bad)["refused"] == "the arguments do not match the tool's schema"
        missing = await client.call_tool("lookup_cve", {"cve_id": "CVE-2020-99999"})
        assert missing.is_error and payload(missing)["errors"] == ["not-found"]
        return run["result"]


def lookups(url: str) -> int:
    with psycopg.connect(plain(url)) as conn:
        row = conn.execute(
            "select coalesce(sum(used), 0) from \"unscheduled\".client_budget where kind = 'lookups'"
        ).fetchone()
    return int(row[0]) if row else 0


def test_the_mcp_server_over_streamable_http(http_url: str, postgres_url: str) -> None:
    before = lookups(postgres_url)
    run = anyio.run(exercise, http_url)
    assert run["approvals"] == []
    # Over HTTP each tool call is counted against the caller's budget, as the routes count theirs.
    assert lookups(postgres_url) - before >= 7


def test_the_mcp_server_over_stdio(stdio_server: StdioServerParameters, postgres_url: str) -> None:
    before = lookups(postgres_url)
    run = anyio.run(exercise, stdio_server)
    assert run["approvals"] == []
    # On a laptop nothing is counted, as the command line counts nothing.
    assert lookups(postgres_url) == before


def test_get_and_delete_on_the_mcp_endpoint_are_refused(http_url: str) -> None:
    """Stateless, the endpoint has no session to end and holds no stream open: both answer 405."""
    import httpx

    for method in ("GET", "DELETE"):
        response = httpx.request(method, http_url, headers={"Accept": "text/event-stream"}, timeout=10)
        assert response.status_code == 405, method
        assert response.headers["content-type"].startswith("application/problem+json")
