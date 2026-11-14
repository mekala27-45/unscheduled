"""The three tests every gate has: a clean pass, a deliberate violation, and a refusal over nothing."""

from __future__ import annotations

from pathlib import Path

import pytest
from unscheduled_core.statements import STATEMENT

from scripts import check_no_em_dash, check_no_model, check_secrets, check_statement, check_vocabulary


def test_dash_gate_passes_clean_text(tmp_path: Path) -> None:
    f = tmp_path / "a.md"
    f.write_text("Ranges use to, asides use commas.\n", encoding="utf-8")
    assert check_no_em_dash.check(tmp_path, [f]) == 1


def test_dash_gate_catches_an_em_dash(tmp_path: Path) -> None:
    f = tmp_path / "a.md"
    f.write_text("one " + chr(0x2014) + " two\n", encoding="utf-8")
    with pytest.raises(ValueError, match="em dash"):
        check_no_em_dash.check(tmp_path, [f])


def test_dash_gate_refuses_nothing(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no files"):
        check_no_em_dash.check(tmp_path, [])


def test_vocabulary_gate_passes_plain_text(tmp_path: Path) -> None:
    f = tmp_path / "a.md"
    f.write_text("The NVD analyzed fewer CVEs after April.\n", encoding="utf-8")
    assert check_vocabulary.check(tmp_path, [f]) == 1


def test_vocabulary_gate_catches_a_banned_phrase(tmp_path: Path) -> None:
    f = tmp_path / "a.md"
    f.write_text("We " + "lever" + "age the lake.\n", encoding="utf-8")
    with pytest.raises(ValueError, match="vocabulary"):
        check_vocabulary.check(tmp_path, [f])


def test_vocabulary_gate_refuses_nothing(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no files"):
        check_vocabulary.check(tmp_path, [])


def test_statement_gate_passes_a_surface_with_it(tmp_path: Path) -> None:
    f = tmp_path / "README.md"
    f.write_text("# x\n\n> " + STATEMENT + "\n", encoding="utf-8")
    assert check_statement.check(tmp_path, [f]) == 1


def test_statement_gate_catches_a_missing_statement(tmp_path: Path) -> None:
    f = tmp_path / "README.md"
    f.write_text("# x\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing the statement"):
        check_statement.check(tmp_path, [f])


def test_statement_gate_refuses_nothing(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no surfaces"):
        check_statement.check(tmp_path, [])


def test_secret_gate_passes_clean_text(tmp_path: Path) -> None:
    f = tmp_path / "a.py"
    f.write_text("DATABASE_URL = os.environ['DATABASE_URL']\n", encoding="utf-8")
    assert check_secrets.check(tmp_path, [f]) == 1


def test_secret_gate_catches_a_connection_string_and_a_token(tmp_path: Path) -> None:
    f = tmp_path / "a.env"
    planted = "postgresql://owner:" + "s3cretPassw0rd" + "@ep-x.neon.tech/db\n" + "ghp_" + "A" * 36 + "\n"
    f.write_text(planted, encoding="utf-8")
    with pytest.raises(ValueError) as err:
        check_secrets.check(tmp_path, [f])
    assert "postgres url" in str(err.value) and "github token" in str(err.value)


def test_secret_gate_refuses_nothing(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no files"):
        check_secrets.check(tmp_path, [])


def _module(root: Path, where: str, text: str) -> Path:
    path = root / where
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_no_model_gate_passes_data_code_and_scoped_model_code(tmp_path: Path) -> None:
    files = [
        _module(
            tmp_path,
            "packages/analysis/a.py",
            "import polars as pl\nfrom sklearn.linear_model import LogisticRegression\n",
        ),
        _module(tmp_path, "packages/models/train.py", "import torch\nfrom transformers import AutoModel\n"),
        _module(tmp_path, "kaggle/kernel.py", "from sentence_transformers import SentenceTransformer\n"),
        _module(tmp_path, "packages/api/serve.py", "import onnxruntime as ort\n"),
    ]
    assert check_no_model.check(tmp_path, files) == 4


@pytest.mark.parametrize(
    ("where", "text"),
    [
        ("packages/api/a.py", "from transformers import AutoModel\n"),
        ("scripts/train.py", "import torch\n"),
        ("packages/analysis/a.py", "import onnxruntime\n"),
        ("packages/models/a.py", "import openai\n"),
        ("kaggle/kernel.py", "from langgraph.graph import StateGraph\n"),
        ("packages/models_extra/a.py", "import torch\n"),
    ],
)
def test_no_model_gate_catches_a_model_import_out_of_place(tmp_path: Path, where: str, text: str) -> None:
    with pytest.raises(ValueError, match="model gate failed"):
        check_no_model.check(tmp_path, [_module(tmp_path, where, text)])


def test_no_model_gate_refuses_nothing(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no files"):
        check_no_model.check(tmp_path, [])
