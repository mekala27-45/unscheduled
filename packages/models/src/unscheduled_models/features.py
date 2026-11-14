"""The features of the fill floors: TF-IDF over the joined text beside the filer and CISA values one
hot, all read from the point in time sets.

Two text representations are compared on development (evaluation/phase2_plan.yaml, band_floor):
word one and two grams, and word grams beside character three to five grams within word
boundaries, both with the plan's settings (min_df 3, at most 200000 features, sublinear term
frequency). A filer or CISA value seen fewer than MIN_FREQUENCY times in train falls into one
infrequent bucket, and a CWE in a filer or CISA list counts only when train holds it at least
MIN_FREQUENCY times. The plan gives the floors the text and the filer and CISA features, so the
affected entries, the exploit code signal and the publication time are left to the exploitation
models of step six. Train holds no CISA value at day 0 (CISA began adding them in 2024), so the
floors learn nothing from those columns, and a CISA value seen first after train encodes as zeros.
"""

from __future__ import annotations

import warnings
from typing import Any

import numpy as np
import pandas as pd
import polars as pl
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MultiLabelBinarizer, OneHotEncoder

from unscheduled_models.sets import METRICS

VARIANTS = ("word", "word_char")
MIN_DF = 3
MIN_FREQUENCY = 20
MAX_FEATURES = 200_000
CATEGORICAL = (
    "filer",
    "filer_type",
    "filer_cvss31_vector",
    "filer_cvss30_vector",
    "filer_cvss40_vector",
    "filer_band",
    *(f"filer_{m}" for m in METRICS),
    "adp_cvss31_vector",
    "adp_band",
    "adp_ssvc_exploitation",
    "adp_ssvc_automatable",
    "adp_ssvc_technical_impact",
)
MULTI = ("filer_cwes", "adp_cwes")
NONE = "(none)"


def _stack(blocks: list[Any]) -> sparse.csr_matrix:
    """The blocks side by side, in canonical form (sorted indices, no duplicates): a solver that
    finds a matrix out of canonical form sorts it in place, which fails on a shared read only copy."""
    matrix = sparse.hstack(blocks, format="csr", dtype=np.float32)
    matrix.sum_duplicates()
    return matrix


class Features:
    """Fit on train once, then transform every split the same way."""

    def __init__(self, variant: str = "word") -> None:
        if variant not in VARIANTS:
            raise ValueError(f"unknown text representation {variant!r}")
        self.variant = variant
        self.word = TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=MIN_DF,
            max_features=MAX_FEATURES,
            sublinear_tf=True,
            dtype=np.float32,
        )
        self.char = (
            TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(3, 5),
                min_df=MIN_DF,
                max_features=MAX_FEATURES,
                sublinear_tf=True,
                dtype=np.float32,
            )
            if variant == "word_char"
            else None
        )
        self.onehot = OneHotEncoder(
            handle_unknown="infrequent_if_exist",
            min_frequency=MIN_FREQUENCY,
            sparse_output=True,
            dtype=np.float32,
        )
        self.multi: dict[str, MultiLabelBinarizer] = {}

    @staticmethod
    def _text(frame: pl.DataFrame) -> list[str]:
        return [str(t) for t in frame.get_column("text").fill_null("").to_list()]

    @staticmethod
    def _categories(frame: pl.DataFrame) -> pd.DataFrame:
        """The categorical columns as strings for the encoder (pandas, as scikit-learn takes it),
        a missing or empty value as one category of its own."""
        cats = frame.select([pl.col(c).cast(pl.String).fill_null(NONE) for c in CATEGORICAL])
        return cats.with_columns(pl.all().replace("", NONE)).to_pandas()

    def _lists(self, frame: pl.DataFrame) -> list[Any]:
        blocks: list[Any] = []
        for column in MULTI:
            binarizer = self.multi[column]
            kept = set(binarizer.classes_)
            lists = [
                [v for v in (values or []) if v in kept] for values in frame.get_column(column).to_list()
            ]
            blocks.append(sparse.csr_matrix(binarizer.transform(lists), dtype=np.float32))
        return blocks

    def fit_transform(self, frame: pl.DataFrame) -> sparse.csr_matrix:
        """Fit on train and return the train matrix, without counting the text twice."""
        text = self._text(frame)
        blocks: list[Any] = [self.word.fit_transform(text)]
        if self.char is not None:
            blocks.append(self.char.fit_transform(text))
        blocks.append(self.onehot.fit_transform(self._categories(frame)))
        for column in MULTI:
            counts: dict[str, int] = {}
            for values in frame.get_column(column).to_list():
                for v in values or []:
                    counts[v] = counts.get(v, 0) + 1
            kept = sorted(v for v, n in counts.items() if n >= MIN_FREQUENCY)
            self.multi[column] = MultiLabelBinarizer(classes=kept, sparse_output=True)
            self.multi[column].fit([kept])
        blocks.extend(self._lists(frame))
        return _stack(blocks)

    def fit(self, frame: pl.DataFrame) -> Features:
        self.fit_transform(frame)
        return self

    def transform(self, frame: pl.DataFrame) -> sparse.csr_matrix:
        text = self._text(frame)
        blocks: list[Any] = [self.word.transform(text)]
        if self.char is not None:
            blocks.append(self.char.transform(text))
        with warnings.catch_warnings():
            # A CISA value train never held encodes as zeros, which the module docstring states.
            warnings.filterwarnings("ignore", message="Found unknown categories")
            blocks.append(self.onehot.transform(self._categories(frame)))
        blocks.extend(self._lists(frame))
        return _stack(blocks)

    def size(self) -> dict[str, int]:
        return {
            "word": len(self.word.vocabulary_),
            "char": len(self.char.vocabulary_) if self.char is not None else 0,
            "onehot": len(self.onehot.get_feature_names_out()),
            "cwe_lists": int(sum(len(b.classes_) for b in self.multi.values())),
        }
