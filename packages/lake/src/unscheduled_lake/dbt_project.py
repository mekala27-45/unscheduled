"""Running the dbt project in dbt/ from Python, one process per command, with the lake's settings.

dbt reads its database, threads and memory from environment variables the profile names, so a run
is fully described by the work database path and the variables passed here. Anonymous usage
statistics and the version check are off: the build makes no network call through dbt.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from unscheduled_core import paths


@dataclass(frozen=True)
class DbtPaths:
    project: Path
    work_db: Path
    target: Path
    logs: Path
    temp: Path


def default_paths(work_dir: Path) -> DbtPaths:
    return DbtPaths(
        project=paths.root() / "dbt",
        work_db=work_dir / "unscheduled.duckdb",
        target=work_dir / "target",
        logs=work_dir / "logs",
        temp=work_dir / "duckdb_tmp",
    )


def environment(p: DbtPaths) -> dict[str, str]:
    p.temp.mkdir(parents=True, exist_ok=True)
    return {
        "UNSCHED_DBT_DB": str(p.work_db),
        "UNSCHED_DUCKDB_TEMP": str(p.temp),
        "DBT_SEND_ANONYMOUS_USAGE_STATS": "false",
        "DBT_VERSION_CHECK": "false",
        "DBT_PARTIAL_PARSE": "true",
        "DBT_PRINTER_WIDTH": "100",
        "DBT_USE_COLORS": "false",
    }


def _command(p: DbtPaths, command: list[str], dbt_vars: dict[str, Any] | None) -> list[str]:
    dbt = Path(sys.executable).with_name("dbt")
    args = [
        str(dbt),
        *command,
        "--project-dir",
        str(p.project),
        "--profiles-dir",
        str(p.project),
        "--target-path",
        str(p.target),
        "--log-path",
        str(p.logs),
    ]
    if dbt_vars:
        args += ["--vars", json.dumps(dbt_vars, sort_keys=True)]
    return args


def invoke(
    p: DbtPaths, command: list[str], dbt_vars: dict[str, Any] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run one dbt command in its own process, so its DuckDB connection closes with it."""
    env = {**os.environ, **environment(p)}
    return subprocess.run(
        _command(p, command, dbt_vars), env=env, capture_output=True, text=True, check=False, cwd=p.project
    )


def compile_inline(p: DbtPaths, sql: str, dbt_vars: dict[str, Any] | None = None) -> str:
    """Compile a piece of SQL that calls the project's macros; return the SQL dbt produced."""
    done = invoke(p, ["compile", "--inline", sql, "--output", "json", "--quiet"], dbt_vars)
    if done.returncode != 0:
        raise RuntimeError(f"dbt could not compile {sql[:80]!r}: {(done.stdout + done.stderr)[-800:]}")
    text = done.stdout
    start = text.find("{")
    if start >= 0:
        payload, _ = json.JSONDecoder().raw_decode(text[start:])
        compiled = payload.get("compiled") if isinstance(payload, dict) else None
        if isinstance(compiled, str) and compiled.strip():
            return compiled
    raise RuntimeError(f"dbt printed no compiled SQL for {sql[:80]!r}")


def run_results(p: DbtPaths) -> dict[str, Any]:
    """dbt's own record of the last run, summarized: every node with its status and timing."""
    path = p.target / "run_results.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    nodes: list[dict[str, Any]] = []
    for r in data.get("results", []):
        uid = str(r.get("unique_id"))
        kind = uid.split(".", 1)[0]
        nodes.append(
            {
                "node": uid,
                "kind": kind,
                "status": r.get("status"),
                "failures": r.get("failures"),
                "seconds": round(float(r.get("execution_time") or 0.0), 2),
                "message": (r.get("message") or "")[:300]
                if r.get("status") not in ("success", "pass")
                else None,
            }
        )
    nodes.sort(key=lambda n: (n["kind"], n["node"]))
    summary: dict[str, dict[str, int]] = {}
    for n in nodes:
        summary.setdefault(n["kind"], {}).setdefault(str(n["status"]), 0)
        summary[n["kind"]][str(n["status"])] += 1
    return {
        "dbt_version": data.get("metadata", {}).get("dbt_version"),
        "elapsed_s": round(float(data.get("elapsed_time") or 0.0), 1),
        "summary": summary,
        "nodes": nodes,
    }
