"""The lake file goes to the release the bundle went to, named by its digest, and only after it."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts import publish_serving


def test_the_lake_waits_for_a_published_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(publish_serving, "PUBLISHED", tmp_path / "published.json")
    monkeypatch.setattr(publish_serving, "LAKE_FILE", tmp_path / "unscheduled.duckdb")
    with pytest.raises(SystemExit, match="publish the bundle first"):
        publish_serving.publish_lake()


def test_the_lake_goes_to_that_release_named_by_its_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lake = tmp_path / "unscheduled.duckdb"
    lake.write_bytes(b"a lake")
    published = tmp_path / "published.json"
    published.write_text(json.dumps({"tag": "serving-202611120700", "id": 42}), encoding="utf-8")
    monkeypatch.setattr(publish_serving, "PUBLISHED", published)
    monkeypatch.setattr(publish_serving, "LAKE_FILE", lake)
    sent: list[tuple[int, Path, str]] = []
    monkeypatch.setattr(publish_serving, "upload", lambda rid, path, name: sent.append((rid, path, name)))
    assert publish_serving.publish_lake() == 0
    assert sent == [(42, lake, f"lake-{hashlib.sha256(b'a lake').hexdigest()[:12]}.duckdb")]
