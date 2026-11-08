# unscheduled. Every target is a step a person or the CI runs; `make help` lists them.
PY := uv run python

.PHONY: help setup gates lint types test cov check-render render probe web clean

help:
	@grep -E '^[a-z-]+:' Makefile | sed 's/:.*//' | sort | tr '\n' ' '; echo

setup:
	uv sync --frozen

gates:
	$(PY) scripts/check_no_em_dash.py
	$(PY) scripts/check_vocabulary.py
	$(PY) scripts/check_statement.py
	$(PY) scripts/check_secrets.py
	$(PY) scripts/check_no_model.py

lint:
	uv run ruff check .
	uv run ruff format --check .

types:
	uv run mypy

test:
	uv run pytest

cov:
	uv run pytest --cov --cov-report=term --cov-fail-under=80

probe:
	$(PY) scripts/probe_hosts.py

web:
	cd web && pnpm install --frozen-lockfile && pnpm build

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
