"""Which agent tests passed in this session, so a module's last test can write its record (evidence.py)."""

from __future__ import annotations

import pytest

from tests.agent import evidence


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.when == "call" or (report.when == "setup" and not report.passed):
        evidence.note(report.nodeid, passed=report.passed)
