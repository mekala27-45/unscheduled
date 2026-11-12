"""The C8 lookup evidence: the cold start and the warm latencies of the live API, from a separate client.

    python scripts/load_test.py [--base-url URL] [--idle-minutes 20] [--lookups 300] [--workers 5]

1. Cold. With --idle-minutes the script first sends nothing for that long, then times the first
   /health and the first lookup. On the free plans Vercel stops an idle container and Neon suspends
   an idle compute after five minutes, so after twenty quiet minutes both start from cold. Another
   client could still have woken them, so the record keeps the wait and the times, not a claim.
2. Warm. --lookups GET /v1/cves/{id} calls over --workers threads, the ids drawn by seed from the
   newest pages of the CVE list. Every latency is kept, and the record gives p50, p95, p99 and the
   count of each status.
3. Persistence from this client, by scripts/check_persistence.py --base-url: the budget count
   carries from one request to the next and every answer names the same data version.
4. schemathesis, by tests/api/test_schemathesis.py: every operation in openapi.json driven with
   generated requests against the app with data loaded; the generator would spend the live daily
   budget in minutes, so it runs in process, as it does in CI.

k6 was the plan for step 2; its release binaries are not reachable from the build machine, so the
same scenario runs here with httpx (DECISIONS.md, 12 November 2026). Every lookup counts against
this client's daily budget of 2,000; the default run spends about 300.

Writes results/load/c8.json and exits 1 when the lookup p95 is over the C8 threshold or a part fails.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
LIVE = "https://unscheduled-api.vercel.app"
OUT = ROOT / "results" / "load" / "c8.json"
PART = ROOT / "results" / "parts" / "load.json"
PERSISTENCE_LIVE = ROOT / "results" / "load" / "persistence_live.json"
PERSISTENCE_LOCAL = ROOT / "results" / "load" / "persistence_independent.json"
C8_LOOKUP_P95_MS = 1500.0
SEED = 20261112
USER_AGENT = "unscheduled-load/0.1 (+https://github.com/mekala27-45/unscheduled)"


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def percentile(values: list[float], q: float) -> float | None:
    """The nearest rank percentile, so a reported value is one that was measured."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, min(len(ordered), round(q / 100 * len(ordered) + 0.5)))
    return round(ordered[rank - 1], 1)


def timed(client: httpx.Client, url: str, **kwargs: Any) -> tuple[int, float]:
    t0 = time.perf_counter()
    try:
        response = client.get(url, **kwargs)
        status = response.status_code
    except httpx.HTTPError:
        status = 0
    return status, round((time.perf_counter() - t0) * 1000, 1)


def sample_ids(client: httpx.Client, base: str, pages: int, count: int) -> list[str]:
    ids: list[str] = []
    cursor: str | None = None
    for _ in range(pages):
        params: dict[str, Any] = {"limit": 100}
        if cursor:
            params["cursor"] = cursor
        body = client.get(f"{base}/v1/cves", params=params).raise_for_status().json()
        ids.extend(i["cve_id"] for i in body.get("items") or [])
        cursor = body.get("next_cursor")
        if not cursor:
            break
    if not ids:
        raise SystemExit("load: the API returned no CVE ids to look up")
    rng = random.Random(SEED)
    return [rng.choice(sorted(ids)) for _ in range(count)]


def cold(base: str, idle_minutes: float) -> dict[str, Any]:
    if idle_minutes > 0:
        print(f"load: sending nothing for {idle_minutes:g} minutes before the cold requests")
        time.sleep(idle_minutes * 60)
    with httpx.Client(timeout=120.0, headers={"User-Agent": USER_AGENT}) as client:
        started = now()
        health_status, health_ms = timed(client, f"{base}/health")
        body = client.get(f"{base}/v1/cves", params={"limit": 1}).json()
        first = (body.get("items") or [{}])[0].get("cve_id")
        lookup_status, lookup_ms = timed(client, f"{base}/v1/cves/{first}") if first else (0, 0.0)
    return {
        "idle_minutes_before": idle_minutes,
        "at": started,
        "health": {"status": health_status, "ms": health_ms},
        "first_lookup": {"cve": first, "status": lookup_status, "ms": lookup_ms},
    }


def warm(base: str, lookups: int, workers: int) -> dict[str, Any]:
    with httpx.Client(timeout=60.0, headers={"User-Agent": USER_AGENT}) as client:
        ids = sample_ids(client, base, pages=3, count=lookups)
        timed(client, f"{base}/health")  # the container and the compute are awake before the clock starts
    latencies: list[float] = []
    statuses: Counter[int] = Counter()
    lock = threading.Lock()
    queue = list(enumerate(ids))

    def worker() -> None:
        with httpx.Client(timeout=60.0, headers={"User-Agent": USER_AGENT}) as client:
            while True:
                with lock:
                    if not queue:
                        return
                    _, cve = queue.pop()
                status, ms = timed(client, f"{base}/v1/cves/{cve}")
                with lock:
                    statuses[status] += 1
                    if status == 200:
                        latencies.append(ms)

    t0 = time.perf_counter()
    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    seconds = time.perf_counter() - t0
    return {
        "lookups": lookups,
        "workers": workers,
        "distinct_cves": len(set(ids)),
        "seconds": round(seconds, 1),
        "per_second": round(lookups / seconds, 1) if seconds else None,
        "statuses": {str(k): v for k, v in sorted(statuses.items())},
        "ok": len(latencies),
        "ms": {
            "p50": percentile(latencies, 50),
            "p95": percentile(latencies, 95),
            "p99": percentile(latencies, 99),
            "max": max(latencies) if latencies else None,
            "mean": round(statistics.fmean(latencies), 1) if latencies else None,
        },
    }


def persistence(args: list[str], out: Path) -> dict[str, Any]:
    """scripts/check_persistence.py in a process of its own; it writes its record only when it passes."""
    out.unlink(missing_ok=True)
    run = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_persistence.py"), *args, "--out", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )
    record: dict[str, Any] = {"exit_code": run.returncode, "file": str(out.relative_to(ROOT))}
    if run.returncode == 0 and out.exists():
        data = json.loads(out.read_text(encoding="utf-8"))
        record["result"] = "pass" if data.get("passed") else "fail"
        record["mode"] = data.get("mode")
    else:
        record["result"] = "fail"
        record["output"] = (run.stdout + run.stderr)[-800:]
    return record


def schemathesis() -> dict[str, Any]:
    target = "tests/api/test_schemathesis.py"
    run = subprocess.run(
        [sys.executable, "-m", "pytest", target, "-p", "no:warnings", "--no-header"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    summary = next(
        (line for line in reversed(run.stdout.splitlines()) if "passed" in line or "failed" in line), ""
    )
    return {
        "test": target,
        "exit_code": run.returncode,
        "summary": summary.strip("= "),
        "result": "pass" if run.returncode == 0 else "fail",
    }


def manifest_part(record: dict[str, Any]) -> dict[str, Any]:
    """The load figures as a manifest part, so documents quote them from the manifest."""
    from unscheduled_core.manifest import ManifestBuilder

    builder = ManifestBuilder(record["finished_at"][:10])
    population = f"the live API at {record['base_url']}, from a separate client"
    common = {"origin": "scripts/load_test.py", "source": "live"}
    cold, warm = record["cold"], record["warm"]
    builder.value("load.idle_minutes", cold["idle_minutes_before"], "min1", population=population, **common)
    builder.value("load.cold_health_ms", cold["health"]["ms"], "ms", population=population, **common)
    builder.value("load.cold_lookup_ms", cold["first_lookup"]["ms"], "ms", population=population, **common)
    builder.value("load.warm_lookups", warm["ok"], "int", population=population, **common)
    builder.value("load.warm_workers", warm["workers"], "int", population=population, **common)
    for q in ("p50", "p95", "p99"):
        builder.value(f"load.warm_{q}_ms", warm["ms"][q], "ms", population=population, **common)
    c8 = record["c8_lookup"]
    builder.value(
        "criteria.c8.verdict",
        f"lookups {c8['verdict']} (p95 {c8['p95_ms']:,.0f} ms against {c8['threshold_p95_ms']:,.0f} ms); "
        "the triage run is measured in Phase 4",
        "text",
        population=population,
        **common,
    )
    return builder.dump()


def commit() -> str | None:
    run = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
    return run.stdout.strip() or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", default=LIVE)
    parser.add_argument("--idle-minutes", type=float, default=0.0)
    parser.add_argument("--lookups", type=int, default=300)
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument(
        "--local-database-url",
        default=None,
        help="a Postgres for the independent connection check (scripts/check_persistence.py --start-server)",
    )
    args = parser.parse_args(argv)
    base = args.base_url.rstrip("/")

    record: dict[str, Any] = {
        "base_url": base,
        "client": "scripts/load_test.py with httpx, a separate process with no database credential",
        "commit": commit(),
        "started_at": now(),
        "cold": cold(base, args.idle_minutes),
    }
    record["warm"] = warm(base, args.lookups, args.workers)
    record["persistence"] = persistence(["--base-url", base], PERSISTENCE_LIVE)
    if args.local_database_url:
        record["persistence_independent"] = persistence(
            ["--start-server", "--database-url", args.local_database_url], PERSISTENCE_LOCAL
        )
    record["schemathesis"] = schemathesis()
    p95 = record["warm"]["ms"]["p95"]
    record["c8_lookup"] = {
        "threshold_p95_ms": C8_LOOKUP_P95_MS,
        "p95_ms": p95,
        "spend": "zero: the Vercel Hobby and Neon free plans, no card on either",
        "verdict": "met" if p95 is not None and p95 <= C8_LOOKUP_P95_MS else "not met",
    }
    record["finished_at"] = now()
    parts = [
        record["persistence"],
        record["schemathesis"],
        record.get("persistence_independent", {"result": "pass"}),
    ]
    parts_ok = all(part["result"] == "pass" for part in parts)
    record["result"] = "pass" if parts_ok and record["c8_lookup"]["verdict"] == "met" else "fail"

    out = args.out or (OUT if base == LIVE else None)
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
        print(f"load: wrote {out}")
    if base == LIVE and record["warm"]["ok"]:
        PART.write_text(json.dumps(manifest_part(record), indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"load: wrote {PART.relative_to(ROOT)}")
    w = record["warm"]
    print(
        f"load: cold health {record['cold']['health']['ms']} ms, first lookup "
        f"{record['cold']['first_lookup']['ms']} ms; warm p50 {w['ms']['p50']} ms, p95 {w['ms']['p95']} ms "
        f"over {w['ok']} of {w['lookups']}; persistence {record['persistence']['result']}, "
        f"schemathesis {record['schemathesis']['result']}; C8 lookups {record['c8_lookup']['verdict']}"
    )
    return 0 if record["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
