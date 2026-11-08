"""The console readings: copied while fresh, refused once they are over thirty days old."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts import probe_platform


def _write(tmp_path: Path, days_ago: int) -> Path:
    read_on = (datetime.now(UTC).date() - timedelta(days=days_ago)).isoformat()
    path = tmp_path / "readings.yaml"
    path.write_text(f"read_on: {read_on}\nneon:\n  plan: Free plan\n", encoding="utf-8")
    return path


def test_fresh_readings_are_copied_with_their_age(tmp_path: Path) -> None:
    data = probe_platform.readings(_write(tmp_path, 3))
    assert data["age_days"] == 3
    assert data["neon"]["plan"] == "Free plan"


def test_stale_readings_are_refused(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="read the consoles again"):
        probe_platform.readings(_write(tmp_path, probe_platform.MAX_AGE_DAYS + 1))


def test_the_committed_readings_name_no_credential() -> None:
    text = (probe_platform.ROOT / "data" / "console_readings.yaml").read_text(encoding="utf-8")
    assert "postgres://" not in text and "postgresql://" not in text and "password" not in text.lower()
