"""Which version of a document a search may read at a time t, in SQL: the version known by t, not yet
replaced by t and not withdrawn by t. Kept apart from corpus.py so the API's search imports no DuckDB."""

from __future__ import annotations

VISIBLE_SQL = (
    "known_from <= {t} and (known_to is null or known_to > {t}) and (withdrawn is null or withdrawn > {t})"
)
