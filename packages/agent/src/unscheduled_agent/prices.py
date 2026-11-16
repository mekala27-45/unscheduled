"""The shadow price of a call, from the locked copy of the mlspend price book.

Every provider of the router is free, so no call costs anything. The shadow price says what the same
tokens would cost at a paid list price: the input and output tokens of a call at the price of the
book's SKU that config/providers.yaml names for the model (the cheapest token SKU of the book, so the
shadow price is a lower bound on a paid call, never a bill). data/prices/book.json is the expanded
book of mekala27-45/mlspend, read once and locked by its sha256 in data/prices/book.lock.json; the
router refuses a book that does not match its lock.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from unscheduled_core import paths
from unscheduled_core.hashing import sha256_file

MILLION = Decimal(1_000_000)


class BookMismatch(ValueError):
    """The price book on disk is not the one its lock names."""


@dataclass(frozen=True)
class Book:
    sha256: str
    per_million: dict[str, Decimal]

    def shadow_usd(self, sku: str, tokens_in: int, tokens_out: int) -> float:
        price_in = self.per_million[f"{sku} input"]
        price_out = self.per_million[f"{sku} output"]
        return float((price_in * tokens_in + price_out * tokens_out) / MILLION)


def load(root: Path | None = None) -> Book:
    base = (root or paths.root()) / "data" / "prices"
    lock = json.loads((base / "book.lock.json").read_text(encoding="utf-8"))
    digest = sha256_file(base / "book.json")
    if digest != lock["sha256"]:
        raise BookMismatch(f"data/prices/book.json is {digest[:12]}, its lock says {lock['sha256'][:12]}")
    book = json.loads((base / "book.json").read_text(encoding="utf-8"))
    per_million = {
        str(row["sku"]): Decimal(str(row["usd"]))
        for row in book["rows"]
        if row.get("unit") == "million_tokens"
    }
    return Book(digest, per_million)
