"""The affected product models: the dictionary, the floor, the retrieval, the measures and the script."""

from __future__ import annotations

import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl
import pytest
from unscheduled_models import product, sets

from scripts import restore_release, train_product

T0 = datetime(2024, 6, 1, tzinfo=UTC)


def write_names(bronze: Path, rows: list[tuple[str, str, str, datetime]]) -> None:
    """A cpe_names bronze table of (id, vendor, product, created) rows, the first id twice."""
    folder = bronze / "cpe_names"
    folder.mkdir(parents=True)
    frame = pl.DataFrame(
        {
            "cpe_name_id": [r[0] for r in rows] + [rows[0][0]],
            "part": ["a"] * (len(rows) + 1),
            "vendor": [r[1] for r in rows] + [rows[0][1]],
            "product": [r[2] for r in rows] + [rows[0][2]],
            "created": [r[3] for r in rows] + [rows[0][3]],
            "last_modified": [r[3] for r in rows] + [datetime(2025, 1, 1, tzinfo=UTC)],
            "deprecated": [False] * len(rows) + [True],
            "fetched_at": [T0] * (len(rows) + 1),
        },
        schema_overrides={
            "created": pl.Datetime("us", "UTC"),
            "last_modified": pl.Datetime("us", "UTC"),
            "fetched_at": pl.Datetime("us", "UTC"),
        },
    )
    frame.write_parquet(folder / "part.parquet")


NAMES = [
    ("1", "acme", "widget_pro", datetime(2020, 1, 1, tzinfo=UTC)),
    ("2", "acme", "widget_lite", datetime(2020, 1, 1, tzinfo=UTC)),
    ("3", "globex", "door", datetime(2020, 1, 1, tzinfo=UTC)),
    ("4", "acme", "widget_pro_max", datetime(2025, 1, 1, tzinfo=UTC)),
    ("5", "easyftp_server_project", "easyftp_server", datetime(2019, 1, 1, tzinfo=UTC)),
    ("6", "initech", "c\\+\\+_toolkit", datetime(2019, 1, 1, tzinfo=UTC)),
]


def test_names_normalize_as_the_plan_says() -> None:
    assert product.normalize("Acme, Inc.") == "acme"
    assert product.normalize("easyftp_server_project") == "easyftp server"
    assert product.normalize("Globex Corporation LLC") == "globex"
    assert product.unquote("c\\+\\+_toolkit") == "c++_toolkit"
    assert product.words("initech", "c\\+\\+_toolkit") == "initech c++ toolkit"


def test_the_dictionary_keeps_the_newest_row_of_a_name(tmp_path: Path) -> None:
    write_names(tmp_path, NAMES)
    pairs = product.dictionary(tmp_path)
    assert pairs.height == len(NAMES)
    widget = pairs.filter(pl.col("key") == "acme:widget_pro").to_dicts()[0]
    assert widget["all_deprecated"] is True and widget["names"] == 1


def test_the_floor_matches_exactly_then_by_ratio_and_only_what_existed(tmp_path: Path) -> None:
    write_names(tmp_path, NAMES)
    floor = product.Floor(product.dictionary(tmp_path))
    t0 = np.datetime64("2024-06-02T00:00:00")
    exact = floor.candidates([{"vendor": "ACME", "product": "Widget Pro"}], t0)
    assert exact[0] == ("acme:widget_pro", 100.0)
    assert "acme:widget_pro_max" not in {k for k, _ in exact}
    later = floor.candidates(
        [{"vendor": "ACME", "product": "Widget Pro"}], np.datetime64("2025-06-01T00:00:00")
    )
    assert "acme:widget_pro_max" in {k for k, _ in later}
    near = floor.candidates([{"vendor": "Acme Inc", "product": "Widget Lite Edition"}], t0)
    assert near[0][0] == "acme:widget_lite"
    no_vendor = floor.candidates([{"vendor": "", "product": "EasyFTP Server"}], t0)
    assert no_vendor[0][0] == "easyftp_server_project:easyftp_server"
    assert floor.candidates(None, t0) == [] and floor.candidates([{"vendor": "", "product": ""}], t0) == []


def test_the_retrieval_ranks_by_cosine_among_what_existed() -> None:
    keys = ["a:one", "b:two", "c:three"]
    vectors = np.eye(3, dtype=np.float32)
    created = np.array(["2020-01-01", "2020-01-01", "2026-01-01"], dtype="datetime64[us]")
    retrieval = product.Retrieval(keys, vectors, created)
    queries = np.array([[0.2, 0.9, 0.95], [1.0, 0.0, 0.0]], dtype=np.float32)
    t0 = np.array(["2024-01-01", "2024-01-01"], dtype="datetime64[us]")
    ranked = retrieval.candidates(queries, t0)
    assert [k for k, _ in ranked[0]] == ["b:two", "a:one"]
    assert ranked[1][0][0] == "a:one"


def test_recall_and_hit_rate_and_the_threshold() -> None:
    ranked = [[("a:x", 100.0), ("b:y", 80.0)], [("c:z", 60.0)], [], [("d:w", 95.0)]]
    labels: list[list[str] | None] = [["b:y", "e:v"], ["c:z"], ["f:u"], None]
    measures = product.recall(ranked, labels)
    assert measures["cves"] == 3
    assert measures["recall_at_1"] == pytest.approx((0 + 1 + 0) / 3)
    assert measures["recall_at_5"] == pytest.approx((0.5 + 1 + 0) / 3)
    assert measures["hit_at_5"] == pytest.approx(2 / 3)
    strict = product.f1_at_1(product.at_threshold(ranked, 90), labels)
    assert strict["named"] == 1 and strict["precision_at_1"] == 0.0
    chosen, search = product.choose_threshold(ranked, labels, thresholds=(50, 60, 90))
    assert chosen == 50 and [s["threshold"] for s in search] == [50, 60, 90]


def test_a_single_table_restores_beside_the_rest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "src"
    write_names(source, NAMES)
    archive = tmp_path / "bronze-cpe_names.tar"
    with tarfile.open(archive, "w") as tar:
        tar.add(source / "cpe_names", arcname="cpe_names")
    root = tmp_path / "repo"
    (root / "data" / "bronze" / "nvd_changes").mkdir(parents=True)
    monkeypatch.setattr(restore_release, "ROOT", root)
    monkeypatch.setattr(restore_release, "download_one", lambda tag, name: (archive, "f" * 64))
    assert restore_release.main(["--release", "lake-20991231", "--table", "cpe_names"]) == 0
    assert (root / "data" / "bronze" / "nvd_changes").is_dir()
    note = json.loads((root / "data" / "bronze" / "cpe_names.release.json").read_text(encoding="utf-8"))
    assert note == {"tag": "lake-20991231", "archive": archive.name, "sha256": "f" * 64}
    assert product.dictionary(root / "data" / "bronze").height == len(NAMES)
    with pytest.raises(SystemExit, match="needs --release"):
        restore_release.main(["--table", "cpe_names"])


class Words:
    """A stand in for the embedder: bags of words, so a query lands near the pair it names."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.vocabulary: dict[str, int] = {}

    def embed(self, texts: list[str], log: Any = None) -> np.ndarray:
        out = np.zeros((len(texts), 64), dtype=np.float32)
        for i, text in enumerate(texts):
            for w in text.lower().replace("_", " ").split():
                out[i, self.vocabulary.setdefault(w, len(self.vocabulary) % 64)] += 1.0
        return out / np.maximum(np.linalg.norm(out, axis=1, keepdims=True), 1e-9)


def test_the_script_writes_the_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    (root / "evaluation").mkdir(parents=True)
    (root / "evaluation" / "phase2_plan.yaml").write_text("defaults:\n  seed: 7\n", encoding="utf-8")
    (root / "evaluation" / "registration.json").write_text(
        json.dumps({"stages": [{"stage": "models", "hash": "abc"}]}), encoding="utf-8"
    )
    (root / "config").mkdir()
    (root / "config" / "models.yaml").write_text(
        "weights:\n  embedding:\n    id: t/m\n    revision: " + "a" * 40 + "\n", encoding="utf-8"
    )
    folder = root / "data" / "sets"
    folder.mkdir(parents=True)
    files: dict[str, Any] = {}
    published = [datetime(2024, 6, 1, 12, tzinfo=UTC), datetime(2024, 6, 3, tzinfo=UTC)]
    for split in ("development", "test", "shadow"):
        inputs = pl.DataFrame(
            {
                "cve_id": ["CVE-1", "CVE-2"],
                "split": [split] * 2,
                "published": published,
                "text": ["acme widget pro overflow", "globex door bypass"],
            }
        )
        pairs = [[{"vendor": "Acme", "product": "Widget Pro"}], [{"vendor": "Globex", "product": "Door"}]]
        product_inputs = pl.DataFrame(
            {"cve_id": ["CVE-1", "CVE-2"], "split": [split] * 2, "filer_pairs": pairs}
        )
        written = [(sets.inputs_name(split), inputs), (sets.product_inputs_name(split), product_inputs)]
        if split == "development":
            labels = pl.DataFrame(
                {
                    "cve_id": ["CVE-1", "CVE-2"],
                    "split": [split] * 2,
                    "nvd_products": [["acme:widget_pro"], ["globex:door"]],
                }
            )
            written.append((sets.product_labels_name(split), labels))
        for name, frame in written:
            frame.write_parquet(folder / name)
            files[name] = {"rows": frame.height, "content_digest": sets.content_digest(folder / name)}
    (root / "results" / "models").mkdir(parents=True)
    (root / "results" / "parts").mkdir(parents=True)
    (root / "results" / "models" / "sets.json").write_text(
        json.dumps({"files": files, "lake_cut": "2026-11-13 06:00:00+00", "lake_release": "lake-x"}),
        encoding="utf-8",
    )
    bronze = root / "data" / "bronze"
    write_names(bronze, NAMES)
    (bronze / "cpe_names.release.json").write_text(
        json.dumps({"tag": "lake-y", "archive": "bronze-cpe_names.tar", "sha256": "e" * 64}), encoding="utf-8"
    )
    weights = tmp_path / "w"
    weights.mkdir()
    fake_files = {"onnx/model.onnx": weights / "m", "tokenizer.json": weights / "t"}
    for path in fake_files.values():
        path.write_bytes(b"x")
    monkeypatch.setattr(train_product.embed, "fetch", lambda _root, _cache: fake_files)
    monkeypatch.setattr(train_product.embed, "Embedder", Words)
    assert train_product.main(["--jobs", "1"], root=root) == 0
    record = json.loads((root / "results" / "models" / "product.json").read_text(encoding="utf-8"))
    assert record["cpe_release"]["tag"] == "lake-y"
    assert record["dev"]["floor"]["recall_at_1"] == pytest.approx(1.0)
    assert record["dictionary"]["pairs"] == len(NAMES)
    part = json.loads((root / "results" / "parts" / "product.json").read_text(encoding="utf-8"))
    assert "models.product.retrieval.dev_recall_at_10" in part["values"]
    assert set(record["predictions"]) == {"development", "test", "shadow"}
    assert (root / "data" / "models" / "product" / "shadow_candidates.parquet").exists()
