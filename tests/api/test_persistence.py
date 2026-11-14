"""The out of process check, run as CI runs it: a child server, then a read back from another process."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_what_the_server_stored_is_read_back_after_it_stops(postgres_url: str) -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "check_persistence.py"),
            "--start-server",
            "--database-url",
            postgres_url,
            "--schema",
            "unscheduled_persistence",
        ],
        cwd=ROOT,
        env={**os.environ, "UNSCHED_ROOT": str(ROOT)},
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    assert "read back from outside the server process" in proc.stdout
    result = json.loads(proc.stdout[: proc.stdout.rindex("}") + 1])
    assert result["read_back"]["budget"] == {"lookups": 2, "matches": 1}
    assert result["read_back"]["match_log"][0]["hashed"] is True
    assert result["read_back"]["migration"] == "0002" and len(result["read_back"]["sync_runs"]) == 1
