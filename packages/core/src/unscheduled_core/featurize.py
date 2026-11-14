"""The models' inputs without scikit-learn, for the API's request time scoring.

One function writes the joined text every text model reads (joined_text, imported by the training
sets). The rest rebuilds, from an exported spec, what the fitted encoders of packages/models do: the
TF-IDF blocks of the band floor (word grams, and character grams within word boundaries), the filer
and CISA values one hot with the infrequent bucket, the CWE lists, and the exploitation model's day 0
row. scripts/export_onnx.py writes the spec and checks every vector built here against
scikit-learn's on a fixed sample of development rows before the spec is kept, so the API and the
training code cannot drift apart unnoticed. Pure Python: a vector is a dict of column to value.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from typing import Any

NONE = "(none)"
WHITE_SPACES = re.compile(r"\s\s+")
CVSS31_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def joined_text(
    description: str | None,
    filer: str | None,
    products: str | None,
    filer_vector: str | None = None,
    adp_band: str | None = None,
    ssvc_exploitation: str | None = None,
) -> str:
    """The one text field every text model reads. It carries the day 0 description, the filer, the
    products, and the structured values the floors also get one hot (the filer vector, the CISA ADP
    band and SSVC exploitation when known at day 0), so a text model and its floor see the same
    inputs."""
    parts = [(description or "").strip()]
    if filer:
        parts.append(f"Filer: {filer}")
    if products:
        parts.append(f"Products: {products}")
    if filer_vector:
        parts.append(f"Filer score: {filer_vector}")
    if adp_band:
        parts.append(f"CISA ADP severity: {adp_band}")
    if ssvc_exploitation:
        parts.append(f"CISA SSVC exploitation: {ssvc_exploitation}")
    return "\n".join(p for p in parts if p)


class Tfidf:
    """A fitted TfidfVectorizer's transform: lower case, the analyzer's terms, counts kept by the
    vocabulary, sublinear term frequency, times the inverse document frequency, unit length."""

    def __init__(self, spec: Mapping[str, Any]) -> None:
        self.analyzer = str(spec["analyzer"])
        if self.analyzer not in ("word", "char_wb"):
            raise ValueError(f"unknown analyzer {self.analyzer!r}")
        self.low, self.high = (int(n) for n in spec["ngram_range"])
        self.lowercase = bool(spec["lowercase"])
        self.sublinear = bool(spec["sublinear_tf"])
        self.token = re.compile(str(spec["token_pattern"]))
        self.vocabulary: dict[str, int] = dict(spec["vocabulary"])
        self.idf: list[float] = [float(v) for v in spec["idf"]]

    def terms(self, text: str) -> list[str]:
        if self.lowercase:
            text = text.lower()
        if self.analyzer == "word":
            tokens = self.token.findall(text)
            out = list(tokens) if self.low == 1 else []
            for n in range(max(self.low, 2), min(self.high, len(tokens)) + 1):
                out.extend(" ".join(tokens[i : i + n]) for i in range(len(tokens) - n + 1))
            return out
        grams: list[str] = []
        for word in WHITE_SPACES.sub(" ", text).split():
            w = f" {word} "
            for n in range(self.low, self.high + 1):
                offset = 0
                grams.append(w[offset : offset + n])
                while offset + n < len(w):
                    offset += 1
                    grams.append(w[offset : offset + n])
                if offset == 0:  # a word shorter than n counts once
                    break
        return grams

    def transform(self, text: str) -> dict[int, float]:
        counts: dict[int, int] = {}
        for term in self.terms(text):
            j = self.vocabulary.get(term)
            if j is not None:
                counts[j] = counts.get(j, 0) + 1
        values = {
            j: ((1.0 + math.log(c)) if self.sublinear else float(c)) * self.idf[j] for j, c in counts.items()
        }
        norm = math.sqrt(sum(v * v for v in values.values()))
        return {j: v / norm for j, v in values.items()} if norm > 0 else values


def category(value: Any) -> str:
    """A categorical value as the encoders saw it: text, a missing or empty value as one category."""
    if value is None:
        return NONE
    text = str(value)
    return text if text else NONE


class OneHot:
    """A fitted OneHotEncoder with min_frequency and handle_unknown infrequent_if_exist: a frequent
    value takes its own column, an infrequent or unseen value the feature's infrequent column when it
    has one, and nothing otherwise."""

    def __init__(self, spec: Sequence[Mapping[str, Any]]) -> None:
        self.features = [(str(f["name"]), dict(f["columns"]), f.get("infrequent")) for f in spec]
        self.width = sum(
            len(cols) + (1 if infrequent is not None else 0) for _, cols, infrequent in self.features
        )

    def transform(self, row: Mapping[str, Any]) -> dict[int, float]:
        out: dict[int, float] = {}
        for name, columns, infrequent in self.features:
            value = category(row.get(name))
            j = columns.get(value, infrequent)
            if j is not None:
                out[int(j)] = 1.0
        return out


class Lists:
    """Fitted multi hot columns: one per kept value of each list feature."""

    def __init__(self, spec: Sequence[Mapping[str, Any]]) -> None:
        self.features = [(str(f["name"]), dict(f["columns"])) for f in spec]

    def transform(self, row: Mapping[str, Any]) -> dict[int, float]:
        out: dict[int, float] = {}
        for name, columns in self.features:
            for value in row.get(name) or []:
                j = columns.get(str(value))
                if j is not None:
                    out[int(j)] = 1.0
        return out


class FloorFeatures:
    """The band floor's full input row: its text blocks, then the structured block, each block's
    columns shifted by the widths before it, as packages/models stacks them."""

    def __init__(self, spec: Mapping[str, Any]) -> None:
        self.text = [Tfidf(block) for block in spec["text"]]
        self.onehot = OneHot(spec["onehot"])
        self.lists = Lists(spec["lists"])
        self.offsets = [int(o) for o in spec["offsets"]]
        self.width = int(spec["width"])

    def transform(self, row: Mapping[str, Any]) -> dict[int, float]:
        text = str(row.get("text") or "")
        parts = [
            *(t.transform(text) for t in self.text),
            self.onehot.transform(row),
            self.lists.transform(row),
        ]
        out: dict[int, float] = {}
        for offset, part in zip(self.offsets, parts, strict=True):
            for j, v in part.items():
                out[offset + j] = v
        return out


def cvss31_metrics(vector: str | None) -> dict[str, str]:
    """The eight base metrics of a CVSS 3.1 vector, or nothing when it is not one."""
    if not vector or not vector.startswith("CVSS:3.1/"):
        return {}
    pairs = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    return {m: pairs[m] for m in CVSS31_METRICS if m in pairs}


_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(value: float) -> float:
    """CVSS 3.1's Roundup: the smallest one decimal number at or above the value, in integers so a
    float error cannot carry it a step up (the specification, appendix A)."""
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def cvss31_score(metrics: Mapping[str, str]) -> float | None:
    """The CVSS 3.1 base score of eight base metrics, by the specification's formula."""
    if set(CVSS31_METRICS) - set(metrics):
        return None
    try:
        changed = metrics["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[metrics["PR"]]
        iss = 1 - (
            (1 - _WEIGHTS["CIA"][metrics["C"]])
            * (1 - _WEIGHTS["CIA"][metrics["I"]])
            * (1 - _WEIGHTS["CIA"][metrics["A"]])
        )
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        exploitability = 8.22 * _WEIGHTS["AV"][metrics["AV"]] * _WEIGHTS["AC"][metrics["AC"]] * pr
        exploitability *= _WEIGHTS["UI"][metrics["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(total, 10.0))


def severity(score: float | None) -> str | None:
    """The CVSS 3.1 qualitative rating of a base score."""
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0.0 else "NONE"


class DayZeroRow:
    """The exploitation model's dense day 0 row: the numbers, the flags, each categorical value as
    its code (unknown as not a number), the CWE lists multi hot, then the band floor's projection."""

    def __init__(self, spec: Mapping[str, Any]) -> None:
        self.numeric = [str(n) for n in spec["numeric"]]
        self.flags = [str(n) for n in spec["flags"]]
        self.codes = [(str(f["name"]), dict(f["codes"])) for f in spec["categorical"]]
        self.lists = [(str(f["name"]), [str(c) for c in f["classes"]]) for f in spec["lists"]]
        self.projection = [str(n) for n in spec["projection"]]
        self.width = len(self.numeric) + len(self.flags) + len(self.codes)
        self.width += sum(len(c) for _, c in self.lists) + len(self.projection)

    def transform(self, row: Mapping[str, Any], projection: Sequence[float]) -> list[float]:
        out: list[float] = []
        for name in self.numeric:
            value = row.get(name)
            out.append(float(value) if value is not None else 0.0)
        out.extend(1.0 if row.get(name) else 0.0 for name in self.flags)
        for name, codes in self.codes:
            code = codes.get(category(row.get(name)))
            out.append(float(code) if code is not None else math.nan)
        for name, classes in self.lists:
            values = {str(v) for v in row.get(name) or []}
            out.extend(1.0 if c in values else 0.0 for c in classes)
        if len(projection) != len(self.projection):
            raise ValueError(f"the projection has {len(projection)} values, not {len(self.projection)}")
        out.extend(float(p) for p in projection)
        return out
