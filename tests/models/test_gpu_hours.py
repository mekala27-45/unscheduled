"""The GPU ledger: requests are read and counted by month, and a month past the ceiling is refused."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import gpu_hours


def write(folder: Path, name: str, **entry: object) -> None:
    base: dict[str, object] = {
        "run": "a run",
        "month": "2026-11",
        "hours_declared": 3,
        "hours_used": 0,
        "status": "not run",
    }
    base.update(entry)
    folder.mkdir(parents=True, exist_ok=True)
    lines = [f"{k}: {v!r}" if isinstance(v, str) else f"{k}: {v}" for k, v in base.items()]
    (folder / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_the_ledger_counts_the_month_and_refuses_the_ceiling(tmp_path: Path) -> None:
    folder = tmp_path / "requests" / "gpu"
    write(folder, "a.yaml")
    write(folder, "b.yaml", status="done", hours_used=2.5)
    write(folder, "c.yaml", month="2026-10", status="done", hours_used=7)
    entry = gpu_hours.ledger(gpu_hours.read_requests(folder), "2026-11", 8.0)
    assert entry == {"month": "2026-11", "ceiling": 8.0, "requests": 2, "runs": 1, "used": 2.5, "left": 5.5}
    part = gpu_hours.manifest_part(entry, "2026-11-13")
    assert part["values"]["models.gpu.hours_left"]["value"] == 5.5
    write(folder, "d.yaml", status="running", hours_declared=6)
    with pytest.raises(SystemExit, match="past the ceiling"):
        gpu_hours.ledger(gpu_hours.read_requests(folder), "2026-11", 8.0)
    write(folder, "e.yaml", status="maybe")
    with pytest.raises(SystemExit, match="status"):
        gpu_hours.read_requests(folder)
