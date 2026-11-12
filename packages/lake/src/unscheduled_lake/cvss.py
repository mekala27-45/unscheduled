"""CVSS vectors checked by the cvss library: does a vector parse, what is its base, what is its score.

The warehouse stores a vector in one canonical form, the base metrics in the order the specification
lists them behind the version prefix (CVSS 2.0 has no prefix), so the same vector written by two
sources, or by one source with its metrics in another order or with temporal metrics appended,
compares equal. The score is the base score of that vector as the library computes it; the score a
source stored is checked against it (quarantine rule Q02), never trusted in its place.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

BASE_METRICS: dict[str, tuple[str, ...]] = {
    "2.0": ("AV", "AC", "Au", "C", "I", "A"),
    "3.0": ("AV", "AC", "PR", "UI", "S", "C", "I", "A"),
    "3.1": ("AV", "AC", "PR", "UI", "S", "C", "I", "A"),
    "4.0": ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"),
}
VERSIONS = tuple(BASE_METRICS)
SCORE_TOLERANCE = 0.1

_PREFIX = re.compile(r"^\(?\s*CVSS:(\d\.\d)/")


@dataclass(frozen=True)
class VectorCheck:
    """What the library made of one vector as a source wrote it.

    vector_score is the score of the vector as written: for CVSS 4.0 a vector with threat metrics
    scores as CVSS-BT. base_score is the score of the base vector alone, the one the facts carry and
    the one the FIRST schema's baseScore names. Sources store either, so a stored score is checked
    against both (quarantine rule Q02, scores_agree).
    """

    version: str
    vector: str
    parses: bool
    base_vector: str | None
    base_score: float | None
    vector_score: float | None
    error: str | None


def declared_version(vector: str, fallback: str) -> str:
    """The version a vector names in its prefix, else the version its row gives."""
    m = _PREFIX.match(vector.strip())
    return m.group(1) if m else fallback


def _text(vector: str, version: str) -> str:
    text = vector.strip().strip("()").strip()
    if version == "2.0":
        return _PREFIX.sub("", text) if text.startswith("CVSS:2") else text
    if not text.startswith("CVSS:"):
        text = f"CVSS:{version}/{text}"
    return text


def check(version: str, vector: str) -> VectorCheck:
    """Parse one vector. A vector that does not parse is reported, never repaired."""
    if version not in BASE_METRICS:
        return VectorCheck(version, vector, False, None, None, None, f"unknown CVSS version {version!r}")
    text = _text(vector, version)
    try:
        if version == "2.0":
            parsed2 = CVSS2(text)
            metrics, score = parsed2.metrics, float(parsed2.base_score)
        elif version == "4.0":
            parsed4 = CVSS4(text)
            metrics, score = parsed4.metrics, float(parsed4.base_score)
        else:
            if not text.startswith(f"CVSS:{version}/"):
                raise CVSSError(f"the vector declares another version than {version}")
            parsed3 = CVSS3(text)
            metrics, score = parsed3.metrics, float(parsed3.base_score)
    except (CVSSError, ValueError, KeyError, IndexError, ArithmeticError) as err:
        return VectorCheck(version, vector, False, None, None, None, f"{type(err).__name__}: {err}"[:300])
    base = "/".join(f"{k}:{metrics[k]}" for k in BASE_METRICS[version])
    base_vector = base if version == "2.0" else f"CVSS:{version}/{base}"
    # The base alone may score differently from the vector as written (CVSS 4.0 with threat
    # metrics), and the facts carry the base, so their score is the score of the base.
    base_only = score if base_vector == text else base_score(version, base_vector)
    return VectorCheck(version, vector, True, base_vector, round(base_only, 1), round(score, 1), None)


def base_score(version: str, base_vector: str) -> float:
    if version == "2.0":
        return float(CVSS2(base_vector).base_score)
    if version == "4.0":
        return float(CVSS4(base_vector).base_score)
    return float(CVSS3(base_vector).base_score)


def band(score: float | None, version: str = "3.1") -> str | None:
    """The qualitative band of a base score: None, Low, Medium, High, Critical (2.0 has three)."""
    if score is None:
        return None
    if version == "2.0":
        return "Low" if score < 4.0 else "Medium" if score < 7.0 else "High"
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def scores_agree(stored: float | None, *computed: float | None) -> bool:
    """A stored score agrees when it is absent or within the tolerance of any score its vector gives."""
    known = [c for c in computed if c is not None]
    if stored is None or not known:
        return True
    return any(abs(stored - c) <= SCORE_TOLERANCE + 1e-9 for c in known)
