"""The CSV the customer's spreadsheet reads, as the legacy script writes it: the contract the adapter keeps.

Read from the golden master in tests/characterization/golden (what the script wrote from sample
feeds): nine columns in this order, a header line of exactly these bytes, comma separated with
minimal quoting and CRLF line ends (Python's csv excel dialect), UTF-8, dates day first as
DD/MM/YYYY, scores as a decimal with one digit or an empty cell, the CVSS v3 severity in capitals or
an empty cell.
"""

from __future__ import annotations

import re
from collections.abc import Callable

COLUMNS: tuple[str, ...] = (
    "CVE",
    "Published",
    "Last Modified",
    "Vendor",
    "Product",
    "CVSS3 Score",
    "CVSS3 Severity",
    "CVSS2 Score",
    "Summary",
)
HEADER = (",".join(COLUMNS) + "\r\n").encode("utf-8")
LINE_END = "\r\n"
DATE_FORMAT = "%d/%m/%Y"
SEVERITIES = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_DATE = re.compile(r"^(0[1-9]|[12]\d|3[01])/(0[1-9]|1[0-2])/\d{4}$")
_SCORE = re.compile(r"^(10\.0|\d\.\d)$")


def _cve(value: str) -> bool:
    return bool(_CVE.match(value))


def _date(value: str) -> bool:
    return bool(_DATE.match(value))


def _score(value: str) -> bool:
    return value == "" or bool(_SCORE.match(value))


def _severity(value: str) -> bool:
    return value == "" or value in SEVERITIES


def _text(value: str) -> bool:
    return "\n" not in value and "\r" not in value


def _name(value: str) -> bool:
    return bool(value) and _text(value)


TYPES: dict[str, tuple[str, Callable[[str], bool]]] = {
    "CVE": ("cve id", _cve),
    "Published": ("date DD/MM/YYYY", _date),
    "Last Modified": ("date DD/MM/YYYY", _date),
    "Vendor": ("name", _name),
    "Product": ("name", _name),
    "CVSS3 Score": ("score or empty", _score),
    "CVSS3 Severity": ("severity or empty", _severity),
    "CVSS2 Score": ("score or empty", _score),
    "Summary": ("one line of text", _text),
}


def type_of(column: str) -> str:
    return TYPES[column][0]


def cell_ok(column: str, value: str) -> bool:
    return TYPES[column][1](value)


def row_problems(row: list[str]) -> list[str]:
    if len(row) != len(COLUMNS):
        return [f"{len(row)} cells for {len(COLUMNS)} columns"]
    return [
        f"{column}: {value!r} is not a {type_of(column)}"
        for column, value in zip(COLUMNS, row, strict=True)
        if not cell_ok(column, value)
    ]
