"""Load data/serving into a throwaway local Postgres through the API's own sync, and read it back.

    python scripts/load_local.py                 # the bundle in data/serving
    python scripts/load_local.py --keep          # leave the cluster running and print its URL

The release is served from memory by the test suite's fake GitHub (tests/api/fixtures/github.py),
so the API downloads, checks every digest and loads the bundle exactly as it does from a real
serving release, one bounded step per call, against a real Postgres started from the local
binaries (tests/api/postgres.py). Then it asks the endpoints the console uses and writes what it
found to results/live/local_load.json: the calls the sync took, the size of every table, and for
each endpoint the status, the time and a digest of the answer. Nothing leaves the machine.

This is the check that the bundle the lake build writes is one the API accepts, and the measure of
how much of the Neon ceiling it takes before the real sync is asked to load it.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import shutil
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import sqlalchemy as sa
from fastapi.testclient import TestClient
from unscheduled_api import migrate
from unscheduled_api.app import create_app
from unscheduled_api.db import make_engine
from unscheduled_api.matching import PackageMatcher, StaticAdvisories
from unscheduled_api.releases import GitHubReleases
from unscheduled_api.services import Services
from unscheduled_api.settings import Settings

from tests.api import postgres
from tests.api.fixtures.bundle import osv_records
from tests.api.fixtures.github import FakeGitHub

SCHEMA = "unscheduled"
PROBES = (
    "/health",
    "/v1/meta",
    "/v1/cves?limit=5",
    "/v1/cves?kev=true&limit=5",
    "/v1/cves?nvd_status=Deferred&limit=5",
    "/v1/cves/CVE-2021-44228",
    "/v1/cves/CVE-2021-44228?as_of=2021-12-12",
    "/v1/cves/CVE-2021-44228/timeline",
    "/v1/backlog",
    "/v1/products",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bundle", type=Path, default=ROOT / "data" / "serving")
    parser.add_argument("--keep", action="store_true", help="leave the cluster running")
    parser.add_argument("--max-calls", type=int, default=400)
    parser.add_argument(
        "--ceiling-mb",
        type=int,
        default=None,
        help="measure past the ceiling of config/budgets.yaml (local only)",
    )
    parser.add_argument("--samples", type=Path, default=None, help="write the body of each probe here")
    args = parser.parse_args(argv)

    started = postgres._local_cluster()
    if isinstance(started, str):
        raise SystemExit(f"load_local: no local Postgres: {started}")
    url, data_dir, tmp = started
    try:
        return run(args, url, tmp)
    finally:
        if args.keep:
            print(f"load_local: the cluster stays up at {url}, its files in {tmp}")
        else:
            binaries = postgres.pg_bin()
            if binaries is not None:
                postgres._as_postgres(
                    [str(binaries / "pg_ctl"), "-D", str(data_dir), "-m", "immediate", "stop"]
                )
            shutil.rmtree(tmp, ignore_errors=True)


def run(args: argparse.Namespace, url: str, tmp: Path) -> int:
    cache = tmp / "bundle-cache"
    env = {
        "UNSCHED_CORS_ORIGINS": "https://unscheduled-triage.vercel.app",
        "UNSCHED_CACHE_DIR": str(cache),
        "UNSCHED_MIGRATE_ON_START": "0",
        "UNSCHED_DB_SCHEMA": SCHEMA,
    }
    settings = Settings.from_env(env, database_url=url)
    if args.ceiling_mb is not None:
        budgets = dataclasses.replace(settings.budgets, storage_ceiling_mb=args.ceiling_mb)
        settings = Settings.from_env(env, database_url=url, budgets=budgets)
    failed = migrate.upgrade(settings)
    if failed is not None:
        raise SystemExit(f"load_local: the migration failed: {failed}")
    engine = make_engine(url, SCHEMA)
    github = FakeGitHub()
    manifest = json.loads((args.bundle / "bundle_manifest.json").read_text(encoding="utf-8"))
    tag = "serving-" + manifest["generated_at"].replace("-", "").replace(":", "").replace("T", "")[:12]
    github.publish(args.bundle, tag, datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
    services = Services.build(
        settings,
        engine=engine,
        releases=GitHubReleases(github.client()),
        matcher=PackageMatcher(StaticAdvisories(osv_records())),
    )
    client = TestClient(create_app(services))

    calls: list[dict[str, Any]] = []
    t0 = time.monotonic()
    final = "stopped"
    for n in range(1, args.max_calls + 1):
        response = client.post("/internal/sync")
        body = response.json()
        calls.append(
            {
                "call": n,
                "http": response.status_code,
                "status": body.get("status"),
                "step": body.get("step"),
                "chunks_done": body.get("chunks_done"),
                "chunks_total": body.get("chunks_total"),
                "storage_bytes": body.get("storage_bytes"),
                "detail": body.get("detail") if response.status_code >= 400 else None,
            }
        )
        print(
            f"sync {n}: {response.status_code} {body.get('status') or body.get('type')} {body.get('step') or ''}",
            flush=True,
        )
        if response.status_code == 200 and body.get("status") in {"done", "current"}:
            final = str(body["status"])
            break
        if response.status_code >= 400:
            final = f"refused: {body.get('type') or response.status_code}: {str(body.get('detail'))[:300]}"
            break
    sync_seconds = round(time.monotonic() - t0, 1)

    with engine.connect() as conn:
        database_bytes = int(
            conn.execute(sa.text("select pg_database_size(current_database())")).scalar_one()
        )
        tables = {
            str(r.name): {
                "rows": int(r.rows),
                "bytes": int(r.bytes),
                "heap_bytes": int(r.heap),
                "toast_bytes": int(r.toast),
                "index_bytes": int(r.indexes),
            }
            for r in conn.execute(
                sa.text(
                    "select c.relname as name, c.reltuples::bigint as rows, pg_total_relation_size(c.oid) as bytes, "
                    "pg_relation_size(c.oid) as heap, coalesce(pg_total_relation_size(nullif(c.reltoastrelid, 0)), 0) "
                    "as toast, pg_indexes_size(c.oid) as indexes "
                    "from pg_class c join pg_namespace n on n.oid = c.relnamespace "
                    "where n.nspname = :schema and c.relkind = 'r' order by bytes desc"
                ),
                {"schema": SCHEMA},
            )
        }
        indexes = {
            str(r.name): int(r.bytes)
            for r in conn.execute(
                sa.text(
                    "select indexrelname as name, pg_relation_size(indexrelid) as bytes from pg_stat_user_indexes "
                    "where schemaname = :schema order by bytes desc"
                ),
                {"schema": SCHEMA},
            )
        }

    probes = []
    for path in PROBES:
        t = time.monotonic()
        response = client.get(path)
        probes.append(
            {
                "path": path,
                "http": response.status_code,
                "ms": round((time.monotonic() - t) * 1000, 1),
                "bytes": len(response.content),
                "sha256": hashlib.sha256(response.content).hexdigest(),
            }
        )
        print(
            f"{path}: {response.status_code} in {probes[-1]['ms']} ms, {len(response.content)} bytes",
            flush=True,
        )
        if args.samples is not None:
            args.samples.mkdir(parents=True, exist_ok=True)
            name = "".join(ch if ch.isalnum() or ch in "-." else "_" for ch in path.strip("/"))
            (args.samples / f"{name}.json").write_bytes(response.content)
    products = client.get("/v1/products").json().get("products") or []
    if products:
        first = products[0]["product_id"]
        response = client.get(f"/v1/products/{first}/exposure")
        probes.append(
            {
                "path": f"/v1/products/{first}/exposure",
                "http": response.status_code,
                "bytes": len(response.content),
            }
        )

    out = {
        "made_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "bundle_generated_at": manifest["generated_at"],
        "lake_digest": manifest["lake_digest"],
        "sync": {"final": final, "calls": len(calls), "seconds": sync_seconds},
        "database_bytes": database_bytes,
        "ceiling_mb": settings.budgets.storage_ceiling_mb,
        "tables": tables,
        "indexes": indexes,
        "probes": probes,
        "calls": calls,
    }
    target = ROOT / "results" / "live" / "local_load.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    print(
        f"load_local: {final} in {len(calls)} calls, {sync_seconds} s; database {database_bytes / 1e6:.1f} MB "
        f"of a {settings.budgets.storage_ceiling_mb} MB ceiling"
    )
    engine.dispose()
    return 0 if final in {"done", "current"} else 1


if __name__ == "__main__":
    sys.exit(main())
