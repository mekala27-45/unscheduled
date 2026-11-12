"""Persistence observed from outside the server: what the API stored, read back by another process.

    python scripts/check_persistence.py --start-server --database-url URL [--port 8799] [--out FILE]
    python scripts/check_persistence.py --base-url https://unscheduled-api.vercel.app [--out FILE]

--start-server starts the API in a child process against URL, in its own schema, and lets it migrate
and make its client salt at start exactly as the container does. It drives the child over HTTP (two
counted lookups, one SBOM match, one sync call), stops it, and only then opens a psycopg connection
of its own and reads back the client budget, the match log, the run ledger, the salt and the
migration. A row that only lived in the server's session, or was never committed, is not there.

--base-url drives a live API from this separate client, where no database credential exists: it
checks that the budget count carries from one request to the next and that every answer names the
same data version.

Nothing secret is printed: the URL is read from the argument or the environment and never echoed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
SBOM = b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}'
LOOKUPS = ("/v1/cves/CVE-2021-44228", "/v1/products")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for(base: str, seconds: float = 90.0) -> dict[str, Any]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"{base}/health", timeout=5.0)
            if response.status_code == 200:
                body: dict[str, Any] = response.json()
                return body
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    raise SystemExit(f"the API at {base} did not answer /health within {seconds:.0f} seconds")


def drive(base: str) -> dict[str, Any]:
    statuses: dict[str, int] = {}
    for path in LOOKUPS:
        statuses[path] = httpx.get(f"{base}{path}", timeout=30.0).status_code
    match = httpx.post(
        f"{base}/v1/match", content=SBOM, headers={"content-type": "application/json"}, timeout=60.0
    )
    statuses["/v1/match"] = match.status_code
    sync = httpx.post(f"{base}/internal/sync", timeout=120.0)
    statuses["/internal/sync"] = sync.status_code
    if match.status_code != 200:
        raise SystemExit(f"POST /v1/match answered {match.status_code}: {match.text[:300]}")
    return {"statuses": statuses, "match_sha256": match.json()["sbom"]["sha256"]}


def read_back(url: str, schema: str, since: datetime) -> dict[str, Any]:
    import psycopg

    plain = url.replace("postgresql+psycopg://", "postgresql://", 1)
    q = f'"{schema}"'
    with psycopg.connect(plain) as conn:
        salt_row = conn.execute(
            f"select value ->> 'salt' from {q}.settings where key = 'client_salt'"
        ).fetchone()
        if salt_row is None or not salt_row[0]:
            raise SystemExit("the client salt the server made at start is not in the settings table")
        client = hashlib.sha256(f"{salt_row[0]}:127.0.0.1".encode()).hexdigest()[:32]
        counted = conn.execute(
            f"select kind, used from {q}.client_budget where client = %s and day = %s",
            (client, datetime.now(UTC).date()),
        ).fetchall()
        budget: dict[str, int] = {str(kind): int(used) for kind, used in counted}
        matches = conn.execute(
            f"select sbom_sha256, components, status, client from {q}.match_log where at >= %s", (since,)
        ).fetchall()
        runs = conn.execute(
            f"select status from {q}.ops_run where kind = 'sync' and started_at >= %s", (since,)
        ).fetchall()
        migration = conn.execute(f"select version_num from {q}.alembic_version").fetchone()
        addresses = conn.execute(f"select count(*) from {q}.match_log where client = '127.0.0.1'").fetchone()
    return {
        "client_hash": client[:8],
        "budget": budget,
        "match_log": [
            {"sbom_sha256": m[0], "components": m[1], "status": m[2], "hashed": m[3] == client}
            for m in matches
        ],
        "sync_runs": [r[0] for r in runs],
        "migration": migration[0] if migration else None,
        "addresses_in_clear": int(addresses[0]) if addresses else 0,
    }


def start_server(url: str, schema: str, port: int) -> subprocess.Popen[bytes]:
    env = {
        **os.environ,
        "DATABASE_URL_UNPOOLED": url,
        "UNSCHED_DB_SCHEMA": schema,
        "UNSCHED_MIGRATE_ON_START": "1",
        "UNSCHED_ROOT": str(ROOT),
    }
    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "unscheduled_api.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
    ]
    return subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def check_local(url: str, schema: str, port: int) -> dict[str, Any]:
    import psycopg

    with psycopg.connect(url.replace("postgresql+psycopg://", "postgresql://", 1), autocommit=True) as conn:
        conn.execute(f'drop schema if exists "{schema}" cascade')
    since = datetime.now(UTC)
    server = start_server(url, schema, port)
    base = f"http://127.0.0.1:{port}"
    try:
        health = wait_for(base)
        driven = drive(base)
    finally:
        server.terminate()
        try:
            server.wait(timeout=30)
        except subprocess.TimeoutExpired:
            server.kill()
    observed = read_back(url, schema, since)
    expected_budget = {"lookups": len(LOOKUPS), "matches": 1}
    problems = []
    if observed["migration"] != "0001":
        problems.append(f"the migration read back is {observed['migration']}")
    if observed["budget"] != expected_budget:
        problems.append(f"the budget read back is {observed['budget']}, expected {expected_budget}")
    if observed["match_log"] != [
        {"sbom_sha256": driven["match_sha256"], "components": 0, "status": "ok", "hashed": True}
    ]:
        problems.append(f"the match log read back is {observed['match_log']}")
    if len(observed["sync_runs"]) != 1:
        problems.append(f"the run ledger read back {observed['sync_runs']} for one sync call")
    if observed["addresses_in_clear"]:
        problems.append("a client address was stored in clear")
    if hashlib.sha256(SBOM).hexdigest() != driven["match_sha256"]:
        problems.append("the match answered with a digest that is not the sha256 of the bytes sent")
    return {
        "mode": "start-server",
        "checked_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "server": {"pid_stopped_before_read": True, "health_status": health["status"]},
        "driven": driven["statuses"],
        "read_back": observed,
        "passed": not problems,
        "problems": problems,
    }


def check_live(base: str) -> dict[str, Any]:
    wait_for(base, 120.0)
    first = httpx.get(f"{base}/v1/products", timeout=60.0)
    second = httpx.get(f"{base}/v1/products", timeout=60.0)
    versions = {first.headers.get("x-data-version"), second.headers.get("x-data-version")}
    problems = []
    remaining = [r.headers.get("x-budget-remaining") for r in (first, second)]
    if None in remaining or int(remaining[0] or 0) - int(remaining[1] or 0) != 1:
        problems.append(f"the budget did not carry from one request to the next: {remaining}")
    if len(versions) != 1:
        problems.append(f"two answers named two data versions: {sorted(v or '' for v in versions)}")
    return {
        "mode": "base-url",
        "base_url": base,
        "checked_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "statuses": [first.status_code, second.status_code],
        "budget_remaining": remaining,
        "data_version": sorted(v or "" for v in versions),
        "passed": not problems,
        "problems": problems,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--start-server", action="store_true")
    parser.add_argument("--base-url", default=None)
    parser.add_argument(
        "--database-url", default=None, help="else UNSCHED_TEST_DATABASE_URL, then DATABASE_URL"
    )
    parser.add_argument("--schema", default="unscheduled_persistence")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.start_server:
        url = (
            args.database_url or os.environ.get("UNSCHED_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
        )
        if not url:
            raise SystemExit("give --database-url, or set UNSCHED_TEST_DATABASE_URL or DATABASE_URL")
        if url.startswith("postgresql://"):
            url = "postgresql+psycopg://" + url[len("postgresql://") :]
        result = check_local(url, args.schema, args.port or free_port())
    elif args.base_url:
        result = check_live(args.base_url.rstrip("/"))
    else:
        parser.error("give --start-server or --base-url")
    text = json.dumps(result, indent=1, sort_keys=True)
    print(text)
    if args.out is not None and result["passed"]:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
    if result["passed"]:
        print("persistence: every row was read back from outside the server process")
        return 0
    print("persistence: " + "; ".join(result["problems"]))
    return 1


if __name__ == "__main__":
    sys.exit(main())
