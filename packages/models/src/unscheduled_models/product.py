"""The affected product models of Phase 2 (evaluation/phase2_plan.yaml: product_floor, product_retrieval).

The candidates are the vendor and product pairs of the NVD CPE dictionary (bronze cpe_names), and a
CVE is offered only the pairs the NVD had created a name for by its day 0, since a name the NVD made
while analyzing that CVE would be the answer leaking in. The label is the vulnerable pairs of the
CVE's NVD configurations at the lake cut (unscheduled_models.sets.product_labels), in the dictionary's
own spelling, vendor:product.

The floor normalizes the filer's affected vendor and product strings and the dictionary's alike
(lower case, the CPE quoting undone, punctuation to spaces, company suffixes and the NVD's own project
suffix dropped from the end), matches them exactly, then by rapidfuzz's token set ratio within the
vendors that match the filer's vendor (exactly, or the three nearest by the same ratio), and ranks
the candidates by the ratio. The retrieval embeds the CVE's joined text and every dictionary pair's
words with the pinned embedding weights and ranks the pairs by cosine.

Recall at k is, per CVE with a label, the share of its labelled pairs among the first k candidates,
averaged over the CVEs; the hit rate at k is the share of CVEs with any labelled pair in the first k.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl
from rapidfuzz import fuzz, process

SUFFIXES = frozenset(
    {
        "inc",
        "incorporated",
        "llc",
        "ltd",
        "limited",
        "corp",
        "corporation",
        "co",
        "company",
        "gmbh",
        "ag",
        "sa",
        "srl",
        "bv",
        "plc",
        "oy",
        "ab",
        "pty",
        "pvt",
        "project",
    }
)
KS = (1, 5, 10)
TOP = 10
VENDOR_NEIGHBOURS = 3
POOL = 300
THRESHOLDS = (50, 60, 70, 80, 90, 100)
# The ratio the floor ranks by: the overlap of the two strings' word sets (rapidfuzz).
RATIO = fuzz.token_set_ratio
_QUOTED = re.compile(r"\\(.)")
_NON_WORD = re.compile(r"[^0-9a-z]+")


def unquote(text: str) -> str:
    """A CPE component with its backslash quoting undone."""
    return _QUOTED.sub(r"\1", text)


def normalize(text: str) -> str:
    words = _NON_WORD.sub(" ", unquote(text).lower()).split()
    while len(words) > 1 and words[-1] in SUFFIXES:
        words.pop()
    return " ".join(words)


def words(vendor: str, product: str) -> str:
    """A dictionary pair as words for the embedding: the quoting undone and underscores as spaces."""
    return f"{unquote(vendor).replace('_', ' ')} {unquote(product).replace('_', ' ')}".strip()


def dictionary(bronze: Path) -> pl.DataFrame:
    """Every vendor and product pair of the CPE dictionary, with the first day the NVD created a name
    for it, from the newest row of every CPE name in bronze."""
    glob = (bronze / "cpe_names" / "**" / "*.parquet").as_posix()
    names = pl.read_parquet(glob, hive_partitioning=False)
    latest = names.sort(["cpe_name_id", "last_modified"]).unique("cpe_name_id", keep="last")
    pairs = (
        latest.group_by("vendor", "product")
        .agg(
            pl.col("created").min().alias("first_created"),
            pl.len().alias("names"),
            pl.col("deprecated").all().alias("all_deprecated"),
        )
        .sort("vendor", "product")
    )
    vendors, products = pairs.get_column("vendor").to_list(), pairs.get_column("product").to_list()
    return pairs.with_columns(
        pl.Series("key", [f"{v}:{p}" for v, p in zip(vendors, products, strict=True)]),
        pl.Series("vendor_norm", [normalize(v) for v in vendors]),
        pl.Series("product_norm", [normalize(p) for p in products]),
        pl.Series("words", [words(v, p) for v, p in zip(vendors, products, strict=True)]),
    )


def day0(frame: pl.DataFrame) -> np.ndarray:
    """The end of each CVE's publication day in UTC, as numpy datetimes, from the inputs' published."""
    ends = frame.select((pl.col("published").dt.truncate("1d") + pl.duration(days=1)).alias("t0"))
    return ends.get_column("t0").dt.replace_time_zone(None).to_numpy()


class Floor:
    """The string floor over the dictionary."""

    def __init__(self, pairs: pl.DataFrame) -> None:
        self.keys = pairs.get_column("key").to_list()
        self.created = pairs.get_column("first_created").dt.replace_time_zone(None).to_numpy()
        vendor_norm = pairs.get_column("vendor_norm").to_list()
        product_norm = pairs.get_column("product_norm").to_list()
        self.full = [f"{v} {p}".strip() for v, p in zip(vendor_norm, product_norm, strict=True)]
        self.exact: dict[tuple[str, str], list[int]] = {}
        self.by_vendor: dict[str, list[int]] = {}
        for i, (v, p) in enumerate(zip(vendor_norm, product_norm, strict=True)):
            self.exact.setdefault((v, p), []).append(i)
            self.by_vendor.setdefault(v, []).append(i)
        self.vendors = sorted(self.by_vendor)
        self.products = product_norm

    def candidates(
        self, filer_pairs: Sequence[dict[str, str]] | None, t0: np.datetime64
    ) -> list[tuple[str, float]]:
        """The ranked candidates for one CVE: exact matches score 100, the rest their token set
        ratio; a pair the NVD had not created a name for by day 0 is never offered."""
        scores: dict[int, float] = {}
        for pair in filer_pairs or []:
            vendor, product = normalize(pair.get("vendor") or ""), normalize(pair.get("product") or "")
            if not vendor and not product:
                continue
            for i in self.exact.get((vendor, product), []):
                scores[i] = 100.0
            query = f"{vendor} {product}".strip()
            if vendor:
                matched = (
                    [vendor]
                    if vendor in self.by_vendor
                    else [
                        v
                        for v, _, _ in process.extract(
                            vendor, self.vendors, scorer=RATIO, limit=VENDOR_NEIGHBOURS
                        )
                    ]
                )
                rows = [i for v in matched for i in self.by_vendor[v]]
                for i in rows:
                    s = RATIO(query, self.full[i])
                    if s > scores.get(i, -1.0):
                        scores[i] = s
            else:
                for _, s, i in process.extract(
                    product, self.products, scorer=RATIO, limit=POOL
                ):
                    if s > scores.get(i, -1.0):
                        scores[i] = s
        live = [(i, s) for i, s in scores.items() if self.created[i] <= t0]
        live.sort(key=lambda item: (-item[1], self.keys[item[0]]))
        return [(self.keys[i], float(s)) for i, s in live[:TOP]]


@dataclass
class Retrieval:
    """The embedding retrieval over the dictionary pairs."""

    keys: list[str]
    vectors: np.ndarray
    created: np.ndarray

    def candidates(
        self, queries: np.ndarray, t0: np.ndarray, batch: int = 256
    ) -> list[list[tuple[str, float]]]:
        out: list[list[tuple[str, float]]] = []
        for start in range(0, len(queries), batch):
            sims = queries[start : start + batch] @ self.vectors.T
            pool = np.argpartition(-sims, min(POOL, sims.shape[1] - 1), axis=1)[:, :POOL]
            for row, idx in enumerate(pool):
                ordered = idx[np.lexsort((idx, -sims[row, idx]))]
                live = [i for i in ordered if self.created[i] <= t0[start + row]][:TOP]
                out.append([(self.keys[i], float(sims[row, i])) for i in live])
        return out


def recall(
    ranked: Sequence[Sequence[tuple[str, float]]], labels: Sequence[Sequence[str] | None]
) -> dict[str, Any]:
    """Recall and hit rate at each k over the CVEs with a label."""
    pairs = [(r, set(lab)) for r, lab in zip(ranked, labels, strict=True) if lab]
    out: dict[str, Any] = {"cves": len(pairs)}
    for k in KS:
        shares = [len({key for key, _ in r[:k]} & lab) / len(lab) for r, lab in pairs]
        hits = [bool({key for key, _ in r[:k]} & lab) for r, lab in pairs]
        out[f"recall_at_{k}"] = float(np.mean(shares)) if shares else float("nan")
        out[f"hit_at_{k}"] = float(np.mean(hits)) if hits else float("nan")
    return out


def at_threshold(
    ranked: Sequence[Sequence[tuple[str, float]]], threshold: float
) -> list[list[tuple[str, float]]]:
    return [[(k, s) for k, s in r if s >= threshold] for r in ranked]


def f1_at_1(
    ranked: Sequence[Sequence[tuple[str, float]]], labels: Sequence[Sequence[str] | None]
) -> dict[str, float]:
    """Precision at 1 over the CVEs the floor names a product for, recall at 1 over every CVE with a
    label, and their harmonic mean (DECISIONS.md, 14 November 2026, the product floor's threshold)."""
    named = [(r[0][0], set(lab)) for r, lab in zip(ranked, labels, strict=True) if lab and r]
    precision = float(np.mean([key in lab for key, lab in named])) if named else 0.0
    rec = recall(ranked, labels)["recall_at_1"]
    f1 = 0.0 if precision + rec == 0 else 2 * precision * rec / (precision + rec)
    return {"precision_at_1": precision, "recall_at_1": rec, "f1_at_1": f1, "named": len(named)}


def choose_threshold(
    ranked: Sequence[Sequence[tuple[str, float]]],
    labels: Sequence[Sequence[str] | None],
    thresholds: Sequence[float] = THRESHOLDS,
    log: Callable[[str], None] | None = None,
) -> tuple[float, list[dict[str, Any]]]:
    """The threshold with the highest F1 at 1 on development; a tie goes to the lower threshold."""
    search, best = [], None
    for t in thresholds:
        result = f1_at_1(at_threshold(ranked, t), labels)
        search.append({"threshold": t, **result})
        if log:
            log(f"product: floor threshold {t} F1 at 1 {result['f1_at_1']:.4f}")
        if best is None or result["f1_at_1"] > best[0]:
            best = (result["f1_at_1"], t)
    assert best is not None
    return best[1], search
