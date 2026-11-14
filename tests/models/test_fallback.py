"""The embeddings and the ModernBERT fallback, with the weights replaced by a fake of the same shape."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import numpy as np
import pytest
from unscheduled_models import embed

from scripts import train_fallback
from tests.models.test_floors import script_root


class FakeEncoding:
    def __init__(self, text: str) -> None:
        words = text.split()[: embed.MAX_TOKENS]
        self.ids = [101, *(hash(w) % 1000 for w in words)]
        self.attention_mask = [1] * len(self.ids)
        self.type_ids = [0] * len(self.ids)


class FakeTokenizer:
    def encode_batch(self, texts: list[str]) -> list[FakeEncoding]:
        return [FakeEncoding(t) for t in texts]


class FakeSession:
    """Hidden states whose first token carries the token count and the first word, so a test can
    tell which text a vector came from."""

    def run(self, _outputs: Any, feeds: dict[str, np.ndarray]) -> list[np.ndarray]:
        ids, mask = feeds["input_ids"], feeds["attention_mask"]
        hidden = np.zeros((ids.shape[0], ids.shape[1], 4), dtype=np.float32)
        hidden[:, 0, 0] = mask.sum(axis=1)
        hidden[:, 0, 1] = ids[:, 1] if ids.shape[1] > 1 else 0
        hidden[:, 0, 2] = 1.0
        return [hidden]


def fake_embedder() -> embed.Embedder:
    e = embed.Embedder.__new__(embed.Embedder)
    e.tokenizer = FakeTokenizer()  # type: ignore[assignment]
    e.session = FakeSession()  # type: ignore[assignment]
    e.inputs = {"input_ids", "attention_mask", "token_type_ids"}
    e.dimension = lambda: 4  # type: ignore[method-assign]
    return e


def test_the_vectors_come_back_in_order_and_unit_length() -> None:
    texts = ["a b c d e f", "a", "a b c", "x y"] * 40
    vectors = fake_embedder().embed(texts)
    assert vectors.shape == (len(texts), 4)
    assert np.allclose(np.linalg.norm(vectors, axis=1), 1.0)
    counts = vectors[:, 0] / vectors[:, 2]
    assert np.allclose(counts[:4], [7, 2, 4, 3])


def test_the_pin_comes_from_the_config() -> None:
    root = Path(__file__).resolve().parents[2]
    model, revision = embed.pinned(root)
    assert model == "BAAI/bge-small-en-v1.5" and len(revision) == 40


def test_a_download_that_differs_from_the_hub_digest_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "/api/models/" in request.url.path:
            files = [{"type": "file", "path": n, "lfs": {"oid": "0" * 64}} for n in embed.FILES]
            return httpx.Response(200, json=files)
        return httpx.Response(200, content=b"not the weights")

    real = httpx.Client

    def client(**kwargs: Any) -> httpx.Client:
        return real(
            transport=httpx.MockTransport(handler), **{k: v for k, v in kwargs.items() if k != "transport"}
        )

    monkeypatch.setattr(embed.httpx, "Client", client)
    root = Path(__file__).resolve().parents[2]
    with pytest.raises(ValueError, match="does not have the digest"):
        embed.fetch(root, tmp_path)


def test_the_fallback_writes_its_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = script_root(tmp_path)
    (root / "config").mkdir(exist_ok=True)
    (root / "config" / "models.yaml").write_text(
        "weights:\n  embedding:\n    id: test/model\n    revision: " + "a" * 40 + "\n", encoding="utf-8"
    )
    weights = tmp_path / "w"
    weights.mkdir()
    files = {name: weights / name.replace("/", "--") for name in embed.FILES}
    for path in files.values():
        path.write_bytes(b"x")
    monkeypatch.setattr(train_fallback.embed, "fetch", lambda _root, _cache: files)

    class Words:
        """Vectors from the words of the fixture text, so the heads have something to learn."""

        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.vocabulary: dict[str, int] = {}

        def embed(self, texts: list[str], log: Any = None) -> np.ndarray:
            out = np.zeros((len(texts), 32), dtype=np.float32)
            for i, t in enumerate(texts):
                for w in t.split():
                    out[i, self.vocabulary.setdefault(w, len(self.vocabulary) % 32)] += 1.0
            return out / np.maximum(np.linalg.norm(out, axis=1, keepdims=True), 1e-9)

    monkeypatch.setattr(train_fallback.embed, "Embedder", Words)
    assert train_fallback.main(["--jobs", "1"], root=root) == 0
    record = json.loads((root / "results" / "models" / "fallback.json").read_text(encoding="utf-8"))
    assert record["model"] == train_fallback.MODEL_NAME
    assert set(record["chosen"]) == {
        "band",
        "cwe",
        *(f"metric_{m}" for m in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]),
    }
    assert record["predictions"]["test"]["rows"] == 50
    # The model reads the embedding beside the floors' structured block; the text alone is kept.
    joint, text = record["designs"]["joint"], record["designs"]["text"]
    assert record["primary"] == "joint" and record["chosen"] == joint["chosen"]
    assert text["width"] == 32 and joint["width"] == 32 + record["structured"]["columns"] > 32
    assert {r["design"] for r in record["search"]} == {"joint", "text"}
    folder = root / "data" / "models" / "fallback"
    for split in ("development", "test", "shadow"):
        assert (folder / f"{split}_probabilities.parquet").exists()
        assert (folder / f"{split}_text_probabilities.parquet").exists()
    part = json.loads((root / "results" / "parts" / "fallback.json").read_text(encoding="utf-8"))
    assert "models.fallback.band.dev" in part["values"]
    assert "models.fallback.text.band.dev" in part["values"]
    # A second run reads the embeddings back instead of embedding again.
    assert (root / "data" / "models" / "fallback" / "train_embeddings.npz").exists()
