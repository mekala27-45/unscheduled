"""The tokenizer of the embedding model, at the revision config/models.yaml pins.

Chunks are measured in the tokens of the model that will embed them, so a chunk never runs past what
the model reads. Only the tokenizer file is fetched, by pinned revision, and kept under data/cache;
its digest is recorded wherever a chunk count is.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx
import yaml
from tokenizers import Tokenizer
from unscheduled_core import paths
from unscheduled_core.hashing import sha256_file

HUB = "https://huggingface.co"


@dataclass(frozen=True)
class Pinned:
    model_id: str
    revision: str
    path: Path
    sha256: str

    def load(self) -> Tokenizer:
        return Tokenizer.from_file(str(self.path))


def embedding_pin(root: Path | None = None) -> tuple[str, str]:
    """The embedding model and its revision, as config/models.yaml pins them."""
    cfg = yaml.safe_load(((root or paths.root()) / "config" / "models.yaml").read_text(encoding="utf-8"))
    weight = cfg["weights"]["embedding"]
    return str(weight["id"]), str(weight["revision"])


def fetch_tokenizer(root: Path | None = None, client: httpx.Client | None = None) -> Pinned:
    """The tokenizer file of the pinned embedding model, downloaded once."""
    model_id, revision = embedding_pin(root)
    target = (root or paths.root()) / "data" / "cache" / "hf" / model_id.replace("/", "--") / revision
    path = target / "tokenizer.json"
    if not path.exists():
        target.mkdir(parents=True, exist_ok=True)
        own = client is None
        http = client or httpx.Client(timeout=httpx.Timeout(60.0), follow_redirects=True)
        try:
            response = http.get(f"{HUB}/{model_id}/resolve/{revision}/tokenizer.json")
            response.raise_for_status()
            path.write_bytes(response.content)
        finally:
            if own:
                http.close()
    return Pinned(model_id, revision, path, sha256_file(path))


def counter(tokenizer: Tokenizer) -> TokenCounter:
    return TokenCounter(tokenizer)


class TokenCounter:
    """How many tokens a text takes, without the two special tokens the model adds around it."""

    def __init__(self, tokenizer: Tokenizer) -> None:
        self.tokenizer = tokenizer

    def __call__(self, text: str) -> int:
        return len(self.tokenizer.encode(text, add_special_tokens=False).ids)
