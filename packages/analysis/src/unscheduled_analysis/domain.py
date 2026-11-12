"""The Q8 domain classifier: how well CVEs the NVD analyzed can be told from the ones it did not.

The one fitted model of Phase 1, and it predicts nothing about any CVE: it measures how different
the two groups are, so Phase 2 knows how much a model trained on NVD labels would be biased toward
the CVEs the NVD chose. A logistic regression on the registered features (filer, filer type, CWE,
published month, which filer vectors are present, and a TF-IDF of the description) is fitted on the
earlier half of the shadow window and scored on the later half. Its scores are never shown as a
value for a CVE.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

import numpy as np
import polars as pl
from numpy.typing import NDArray
from scipy import sparse
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import OneHotEncoder

C = 1.0
MIN_DF = 5
MAX_FEATURES = 30000
WINDOW_START = date(2026, 4, 15)


@dataclass
class Fitted:
    model: LogisticRegression
    names: list[str]
    groups: list[str]
    filer: OneHotEncoder
    cwe: CountVectorizer
    words: TfidfVectorizer


def _cwe_text(lists: list[list[str] | None]) -> list[str]:
    return [" ".join(sorted(x for x in (v or []) if x.startswith("CWE-"))) for v in lists]


def _months(published: list[date]) -> NDArray[np.float64]:
    return np.array(
        [[(d.year - WINDOW_START.year) * 12 + d.month - WINDOW_START.month] for d in published],
        dtype=np.float64,
    )


def _matrix(frame: pl.DataFrame, fitted: Fitted | None) -> tuple[sparse.csr_matrix, Fitted]:
    cats = frame.select(["filer", "filer_type"]).to_numpy().astype(str)
    cwe_text = _cwe_text(frame.get_column("filer_cwes").to_list())
    desc = frame.get_column("description").fill_null("").to_list()
    months = _months(frame.get_column("published_month").to_list())
    flags = frame.select(["has_filer_cvss3", "has_filer_cvss40"]).to_numpy().astype(np.float64)
    if fitted is None:
        filer = OneHotEncoder(handle_unknown="ignore", min_frequency=3, sparse_output=True)
        cwe = CountVectorizer(token_pattern=r"CWE-\d+", lowercase=False, binary=True)
        words = TfidfVectorizer(
            min_df=MIN_DF, max_features=MAX_FEATURES, ngram_range=(1, 2), sublinear_tf=True, dtype=np.float64
        )
        parts = [filer.fit_transform(cats), cwe.fit_transform(cwe_text), words.fit_transform(desc)]
        names = (
            [f"filer or type: {n}" for n in filer.get_feature_names_out(["filer", "filer_type"])]
            + [f"cwe: {n}" for n in cwe.get_feature_names_out()]
            + [f"word: {n}" for n in words.get_feature_names_out()]
            + ["published month (months since 2026-04)", "filer CVSS 3.x present", "filer CVSS 4.0 present"]
        )
        groups = (
            [
                "filer"
                if n.startswith("filer or type: filer_") and not n.startswith("filer or type: filer_type")
                else "filer type"
                for n in names[: parts[0].shape[1]]
            ]
            + ["cwe"] * parts[1].shape[1]
            + ["description"] * parts[2].shape[1]
            + ["month", "vector", "vector"]
        )
        fitted = Fitted(LogisticRegression(), names, groups, filer, cwe, words)
    else:
        parts = [fitted.filer.transform(cats), fitted.cwe.transform(cwe_text), fitted.words.transform(desc)]
    x = sparse.hstack([*parts, sparse.csr_matrix(months / 6.0), sparse.csr_matrix(flags)], format="csr")
    return x, fitted


def fit(train: pl.DataFrame) -> Fitted:
    x, fitted = _matrix(train, None)
    y = train.get_column("nvd_analyzed").cast(pl.Int64).to_numpy()
    model = LogisticRegression(C=C, solver="liblinear", max_iter=2000, random_state=0)
    model.fit(x, y)
    fitted.model = model
    return fitted


def score(fitted: Fitted, frame: pl.DataFrame) -> NDArray[np.float64]:
    x, _ = _matrix(frame, fitted)
    probabilities: NDArray[np.float64] = fitted.model.predict_proba(x)[:, 1]
    return probabilities


def top_features(
    fitted: Fitted, n: int = 15
) -> tuple[list[tuple[str, str, float]], list[tuple[str, str, float]]]:
    coef = fitted.model.coef_[0]
    order = np.argsort(coef, kind="mergesort")
    toward = [(fitted.names[i], fitted.groups[i], float(coef[i])) for i in order[::-1][:n]]
    away = [(fitted.names[i], fitted.groups[i], float(coef[i])) for i in order[:n]]
    return toward, away
