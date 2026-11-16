"""Text to vectors and pairs to scores on the CPU with ONNX Runtime, from files pinned by revision.

The embedding model is BAAI/bge-small-en-v1.5 at the revision config/models.yaml pins, read from the
ONNX export its repository carries at that revision: CLS pooling, unit length, and the query
instruction of its model card in front of every query and of nothing else. The reranker is
cross-encoder/ms-marco-MiniLM-L6-v2 at the revision config/agent.yaml pins, read from the int8 ONNX
file its repository carries (quantized for AVX2, which every runner has): one relevance logit per
query and passage pair. Every file is downloaded once into data/cache/hf and recorded with its
sha256, so a run names the exact bytes it scored with.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import numpy as np
import onnxruntime as ort
import yaml
from tokenizers import Tokenizer
from unscheduled_core import paths
from unscheduled_core.hashing import sha256_file

HUB = "https://huggingface.co"
QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "
DIMENSIONS = 384


@dataclass(frozen=True)
class Pinned:
    model_id: str
    revision: str
    files: dict[str, Path]

    def digests(self) -> dict[str, str]:
        return {name: sha256_file(path) for name, path in sorted(self.files.items())}


def fetch(model_id: str, revision: str, names: Sequence[str], root: Path | None = None) -> Pinned:
    """The named files of a model repository at one revision, downloaded once."""
    folder = (root or paths.root()) / "data" / "cache" / "hf" / model_id.replace("/", "--") / revision
    files: dict[str, Path] = {}
    with httpx.Client(timeout=httpx.Timeout(300.0), follow_redirects=True) as http:
        for name in names:
            path = folder / name
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                partial = path.with_name(path.name + ".part")
                with http.stream("GET", f"{HUB}/{model_id}/resolve/{revision}/{name}") as response:
                    response.raise_for_status()
                    with partial.open("wb") as handle:
                        for block in response.iter_bytes(1 << 20):
                            handle.write(block)
                partial.replace(path)
            files[name] = path
    return Pinned(model_id, revision, files)


def pins(root: Path | None = None) -> dict[str, dict[str, str]]:
    """The embedding model as config/models.yaml pins it and the reranker as config/agent.yaml does."""
    base = root or paths.root()
    models = yaml.safe_load((base / "config" / "models.yaml").read_text(encoding="utf-8"))["weights"]
    agent = yaml.safe_load((base / "config" / "agent.yaml").read_text(encoding="utf-8"))["models"]
    embedding = models["embedding"]
    return {
        "embedding": {
            "id": str(embedding["id"]),
            "revision": str(embedding["revision"]),
            "onnx": "onnx/model.onnx",
        },
        "reranker": {k: str(v) for k, v in agent["reranker"].items() if k in ("id", "revision", "onnx")},
    }


def _session(path: Path, threads: int) -> ort.InferenceSession:
    options = ort.SessionOptions()
    options.intra_op_num_threads = threads
    options.inter_op_num_threads = 1
    options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    return ort.InferenceSession(str(path), options, providers=["CPUExecutionProvider"])


def _tokenizer(path: Path, max_length: int) -> Tokenizer:
    tokenizer = Tokenizer.from_file(str(path))
    tokenizer.enable_truncation(max_length=max_length)
    pad = tokenizer.token_to_id("[PAD]")
    tokenizer.enable_padding(pad_id=pad if pad is not None else 0, pad_token="[PAD]")
    return tokenizer


def _feeds(session: ort.InferenceSession, encodings: Sequence[Any]) -> dict[str, np.ndarray]:
    ids = np.asarray([e.ids for e in encodings], dtype=np.int64)
    mask = np.asarray([e.attention_mask for e in encodings], dtype=np.int64)
    types = np.asarray([e.type_ids for e in encodings], dtype=np.int64)
    available = {"input_ids": ids, "attention_mask": mask, "token_type_ids": types}
    return {i.name: available[i.name] for i in session.get_inputs()}


class Encoder:
    """Unit vectors of 384 dimensions, rounded to half precision as Postgres stores them."""

    def __init__(self, tokenizer: Path, model: Path, *, max_length: int = 512, threads: int = 4) -> None:
        self.tokenizer = _tokenizer(tokenizer, max_length)
        self.session = _session(model, threads)

    def encode(self, texts: Sequence[str], batch_size: int = 32) -> np.ndarray:
        out = np.zeros((len(texts), DIMENSIONS), dtype=np.float16)
        order = sorted(range(len(texts)), key=lambda i: len(texts[i]))
        for start in range(0, len(order), batch_size):
            batch = order[start : start + batch_size]
            encodings = self.tokenizer.encode_batch([texts[i] for i in batch])
            hidden = self.session.run(None, _feeds(self.session, encodings))[0]
            cls = np.asarray(hidden[:, 0, :], dtype=np.float32)
            cls /= np.linalg.norm(cls, axis=1, keepdims=True)
            out[batch] = cls.astype(np.float16)
        return out

    def encode_queries(self, texts: Sequence[str], batch_size: int = 32) -> np.ndarray:
        return self.encode([QUERY_INSTRUCTION + t for t in texts], batch_size)


class CrossEncoder:
    """A relevance logit for each passage against one query; higher is more relevant."""

    def __init__(self, tokenizer: Path, model: Path, *, max_length: int = 512, threads: int = 4) -> None:
        self.tokenizer = _tokenizer(tokenizer, max_length)
        self.session = _session(model, threads)

    def score(self, query: str, passages: Sequence[str], batch_size: int = 32) -> np.ndarray:
        scores = np.zeros(len(passages), dtype=np.float32)
        for start in range(0, len(passages), batch_size):
            pairs = [(query, p) for p in passages[start : start + batch_size]]
            encodings = self.tokenizer.encode_batch(pairs)
            logits = self.session.run(None, _feeds(self.session, encodings))[0]
            scores[start : start + len(pairs)] = np.asarray(logits, dtype=np.float32).reshape(len(pairs), -1)[
                :, 0
            ]
        return scores
