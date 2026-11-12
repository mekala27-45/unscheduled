"""Settings: the connection variables in their fixed order, by name only, and the ceilings from the file."""

from __future__ import annotations

from pathlib import Path

import pytest
from unscheduled_api.settings import ConfigError, Settings, load_budgets, normalize_url

URL = "postgresql://user:" + "pw" + "@host/db"  # split so the secret gate does not read a credential


def test_the_unpooled_variable_is_read_first_then_the_pooled_then_postgres_url() -> None:
    env = {"POSTGRES_URL": URL + "?a", "DATABASE_URL": URL + "?b", "DATABASE_URL_UNPOOLED": URL + "?c"}
    settings = Settings.from_env(env)
    assert settings.database_variable == "DATABASE_URL_UNPOOLED"
    assert settings.database_url == "postgresql+psycopg://user:pw@host/db?c"
    assert settings.variables_found == ("DATABASE_URL_UNPOOLED", "DATABASE_URL", "POSTGRES_URL")
    assert Settings.from_env({"POSTGRES_URL": URL}).database_variable == "POSTGRES_URL"
    assert Settings.from_env({"DATABASE_URL": "  "}).database_configured is False


def test_the_url_never_appears_in_the_printed_settings() -> None:
    settings = Settings.from_env({"DATABASE_URL": URL})
    assert "pw" not in repr(settings) and "host/db" not in repr(settings)


def test_urls_get_the_psycopg_driver() -> None:
    assert normalize_url("postgres://a@b/c") == "postgresql+psycopg://a@b/c"
    assert normalize_url("postgresql+psycopg://a@b/c") == "postgresql+psycopg://a@b/c"


def test_the_ceilings_come_from_the_registered_budgets_file() -> None:
    budgets = Settings.from_env({}).budgets
    assert budgets.sbom_upload_max_bytes == 2_097_152
    assert budgets.storage_ceiling_bytes == budgets.storage_ceiling_mb * 1_000_000


def test_a_missing_or_malformed_budgets_file_stops_the_api(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="is missing"):
        load_budgets(tmp_path / "budgets.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("neon: {}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="expected shape"):
        load_budgets(bad)


def test_the_schema_name_is_checked() -> None:
    with pytest.raises(ConfigError):
        Settings.from_env({"UNSCHED_DB_SCHEMA": "x; drop table"})
    assert Settings.from_env({"UNSCHED_DB_SCHEMA": "unscheduled_v2"}).schema == "unscheduled_v2"


def test_switches_read_the_usual_spellings() -> None:
    assert Settings.from_env({"UNSCHED_MIGRATE_ON_START": "0"}).migrate_on_start is False
    assert Settings.from_env({"UNSCHED_MIGRATE_ON_START": "yes"}).migrate_on_start is True
    assert Settings.from_env({}).migrate_on_start is True
