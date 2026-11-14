"""The serving measurement: folder sizes skip links, the part carries every measure with its unit and
machine, and a missing serving file stops the run before anything is built."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import measure_serving


def record(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "machine": {"system": "Linux-test", "cpus": 2, "python": "3.12.0"},
        "environment_megabytes": 412.3,
        "predict_megabytes": 10.1,
        "embedding_megabytes": None,
        "runs": 5,
        "warm": 50,
        "load_ms_median": 640,
        "first_ms_median": 18,
        "warm_ms_p50": 4.2,
    }
    base.update(over)
    return base


def test_folder_bytes_counts_files_and_skips_links(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"x" * 10)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b").write_bytes(b"y" * 5)
    (tmp_path / "link").symlink_to(tmp_path / "a")
    assert measure_serving.folder_bytes(tmp_path) == 15


def test_the_part_names_each_measure_and_the_machine() -> None:
    part = measure_serving.manifest_part(record(), "2026-11-13")
    values = part["values"]
    assert set(values) == {
        "models.serving.environment_megabytes",
        "models.serving.predict_megabytes",
        "models.serving.load_ms",
        "models.serving.first_ms",
        "models.serving.warm_p50_ms",
    }
    assert values["models.serving.load_ms"]["value"] == 640
    assert "median of 5" in values["models.serving.load_ms"]["provenance"]["population"]
    assert "2 CPUs" in values["models.serving.warm_p50_ms"]["provenance"]["population"]
    with_embedding = measure_serving.manifest_part(record(embedding_megabytes=133.0), "2026-11-13")
    assert with_embedding["values"]["models.serving.embedding_megabytes"]["value"] == 133.0


def test_a_missing_serving_file_stops_the_run(tmp_path: Path) -> None:
    (tmp_path / "models" / "serving").mkdir(parents=True)
    with pytest.raises(SystemExit, match="models/serving lacks"):
        measure_serving.main([], root=tmp_path)
