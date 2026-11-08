"""Capture the golden master: run the legacy script once per scenario and keep what it produced.

uv run python -m tests.characterization.regenerate

A characterization pins behavior as found, so this runs once, when the behavior is first captured,
and again only on purpose: the diff of the golden files then shows exactly what changed.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from tests.characterization import harness


def capture(name: str, sample: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="unsched-legacy-") as tmp:
        root = Path(tmp)
        if sample:
            base_url, years = harness.sample_feeds(root)
        else:
            base_url, years = harness.retired_feeds(root), None
        result = harness.run(root, base_url, years)
    harness.GOLDEN.mkdir(parents=True, exist_ok=True)
    (harness.GOLDEN / f"{name}.csv").write_bytes(result.csv_bytes)
    (harness.GOLDEN / f"{name}.mail.txt").write_text(result.mail, encoding="utf-8")
    (harness.GOLDEN / f"{name}.stdout.txt").write_text(
        f"exit code {result.exit_code}\n{result.stdout}", encoding="utf-8"
    )
    print(f"golden master: {name}: {len(result.csv_bytes)} bytes of CSV, exit code {result.exit_code}")


if __name__ == "__main__":
    capture("sample_feeds", sample=True)
    capture("retired_feeds", sample=False)
