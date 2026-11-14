"""Sentence embeddings from the pinned weights of config/models.yaml (embedding), run with onnxruntime.

The weights are the ONNX export BAAI publishes beside the model, at the revision config/models.yaml
pins, checked against the SHA-256 the Hub records for the file before it is opened. A text is
tokenized by the model's own tokenizer, cut at MAX_TOKENS, and embedded as the model is meant to be
used: the hidden state of the first token, scaled to unit length, so a dot product is the cosine.
The texts are embedded in batches of similar length and come back in the order they were given.
No PyTorch is needed: the same file serves the API later.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Sequence
from pathlib import Path

import httpx
import numpy as np
import onnxruntime as ort
import yaml
from tokenizers import Tokenizer

MAX_TOKENS = 256
BATCH = 64
FILES = ("onnx/model.onnx", "tokenizer.json")
HUB = "https://huggingface.co"


def runtime_version() -> str:
    """The onnxruntime version, for a record written outside this package."""
    return str(ort.__version__)


def pinned(root: Path) -> tuple[str, str]:
    """The model id and the revision config/models.yaml pins for the embedding."""
    config = yaml.safe_load((root / "config" / "models.yaml").read_text(encoding="utf-8"))
    weights = config["weights"]["embedding"]
    return str(weights["id"]), str(weights["revision"])


def hub_digests(model: str, revision: str, client: httpx.Client) -> dict[str, str]:
    """The SHA-256 the Hub records for each file stored in LFS at the revision."""
    response = client.get(f"{HUB}/api/models/{model}/tree/{revision}", params={"recursive": "true"})
    response.raise_for_status()
    return {
        str(e["path"]): str(e["lfs"]["oid"])
        for e in response.json()
        if e.get("type") == "file" and e.get("lfs")
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch(root: Path, cache: Path) -> dict[str, Path]:
    """The weights and the tokenizer at the pinned revision, downloaded once into the cache."""
    model, revision = pinned(root)
    folder = cache / model.replace("/", "--") / revision
    folder.mkdir(parents=True, exist_ok=True)
    out: dict[str, Path] = {}
    with httpx.Client(timeout=300.0, follow_redirects=True) as client:
        digests = hub_digests(model, revision, client)
        for name in FILES:
            target = folder / name.replace("/", "--")
            expected = digests.get(name)
            if not target.exists() or (expected and sha256(target) != expected):
                with client.stream("GET", f"{HUB}/{model}/resolve/{revision}/{name}") as response:
                    response.raise_for_status()
                    tmp = target.with_name(target.name + ".part")
                    with tmp.open("wb") as handle:
                        for chunk in response.iter_bytes(1 << 20):
                            handle.write(chunk)
                    tmp.replace(target)
            if expected and sha256(target) != expected:
                raise ValueError(f"{name} at {revision} does not have the digest the Hub records")
            out[name] = target
    return out


class Embedder:
    def __init__(self, files: dict[str, Path], threads: int = 0) -> None:
        self.tokenizer = Tokenizer.from_file(str(files["tokenizer.json"]))
        self.tokenizer.enable_truncation(max_length=MAX_TOKENS)
        self.tokenizer.no_padding()
        options = ort.SessionOptions()
        if threads:
            options.intra_op_num_threads = threads
        options.inter_op_num_threads = 1
        self.session = ort.InferenceSession(
            str(files["onnx/model.onnx"]), sess_options=options, providers=["CPUExecutionProvider"]
        )
        self.inputs = {i.name for i in self.session.get_inputs()}

    def _batch(self, texts: Sequence[str]) -> np.ndarray:
        encodings = self.tokenizer.encode_batch(list(texts))
        width = max(len(e.ids) for e in encodings)
        ids = np.zeros((len(encodings), width), dtype=np.int64)
        mask = np.zeros_like(ids)
        types = np.zeros_like(ids)
        for i, e in enumerate(encodings):
            ids[i, : len(e.ids)] = e.ids
            mask[i, : len(e.ids)] = e.attention_mask
            types[i, : len(e.ids)] = e.type_ids
        feeds = {"input_ids": ids, "attention_mask": mask, "token_type_ids": types}
        hidden = self.session.run(None, {k: v for k, v in feeds.items() if k in self.inputs})[0]
        first = np.asarray(hidden[:, 0, :], dtype=np.float32)
        unit: np.ndarray = first / np.linalg.norm(first, axis=1, keepdims=True)
        return unit

    def embed(self, texts: Sequence[str], log: Callable[[str], None] | None = None) -> np.ndarray:
        """Unit vectors for the texts, in the order given, batched by token count."""
        lengths = [len(e.ids) for e in self.tokenizer.encode_batch(list(texts))]
        order = np.argsort(lengths, kind="stable")
        out = np.empty((len(texts), self.dimension()), dtype=np.float32)
        started = time.monotonic()
        for start in range(0, len(texts), BATCH):
            chosen = order[start : start + BATCH]
            out[chosen] = self._batch([texts[i] for i in chosen])
            if log and (start // BATCH) % 200 == 0:
                done = start + len(chosen)
                log(f"embed: {done} of {len(texts)} in {time.monotonic() - started:.0f}s")
        return out

    def dimension(self) -> int:
        shape = self.session.get_outputs()[0].shape
        return int(shape[-1])
