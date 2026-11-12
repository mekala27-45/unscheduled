"""A real Postgres for the API and CLI tests, found or started once per session.

The API uses JSONB, text arrays, advisory locks, COPY and ON CONFLICT, so a SQLite stand in would
test a database the service never talks to. In order:

1. UNSCHED_TEST_DATABASE_URL, when it is set (CI, or a developer's own server);
2. a temporary cluster from the local Postgres binaries, run as the postgres user when the tests run
   as root, because Postgres refuses to run as root;
3. a testcontainers Postgres, when a Docker daemon answers.

When none of the three is possible the tests that need it skip with the reason, and CI turns the skip
into a failure by setting UNSCHED_REQUIRE_POSTGRES=1.
"""

from __future__ import annotations

import atexit
import os
import pwd
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

PG_BIN_CANDIDATES = (
    "/usr/lib/postgresql/17/bin",
    "/usr/lib/postgresql/16/bin",
    "/usr/lib/postgresql/15/bin",
    "/usr/local/pgsql/bin",
    "/opt/homebrew/bin",
)
URL_VARIABLE = "UNSCHED_TEST_DATABASE_URL"


def _skip(reason: str) -> None:
    if os.environ.get("UNSCHED_REQUIRE_POSTGRES") == "1":
        pytest.fail(f"a real Postgres is required here and none was found: {reason}")
    pytest.skip(f"no Postgres for the database tests: {reason}")


def pg_bin() -> Path | None:
    for candidate in PG_BIN_CANDIDATES:
        if (Path(candidate) / "pg_ctl").exists() and (Path(candidate) / "initdb").exists():
            return Path(candidate)
    found = shutil.which("pg_ctl")
    return Path(found).parent if found and (Path(found).parent / "initdb").exists() else None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _as_postgres(command: list[str]) -> subprocess.CompletedProcess[str]:
    if os.geteuid() == 0:
        command = ["runuser", "-u", "postgres", "--", *command]
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)


def _local_cluster() -> tuple[str, Path, Path] | str:
    """(url, data dir, tmp dir) of a running temporary cluster, or the reason there is none."""
    binaries = pg_bin()
    if binaries is None:
        return "no local Postgres binaries"
    tmp = Path(tempfile.mkdtemp(prefix="unsched-pg-"))
    if os.geteuid() == 0:
        try:
            user = pwd.getpwnam("postgres")
        except KeyError:
            shutil.rmtree(tmp, ignore_errors=True)
            return "running as root and there is no postgres user to run the server"
        os.chown(tmp, user.pw_uid, user.pw_gid)
    data = tmp / "data"
    init = _as_postgres(
        [str(binaries / "initdb"), "-D", str(data), "-A", "trust", "-U", "postgres", "--no-sync"]
    )
    if init.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        return f"initdb failed: {init.stderr[-300:]}"
    port = _free_port()
    options = f"-p {port} -k {tmp} -c listen_addresses=127.0.0.1 -c fsync=off -c max_connections=60"
    start = _as_postgres(
        [
            str(binaries / "pg_ctl"),
            "-D",
            str(data),
            "-o",
            options,
            "-l",
            str(tmp / "server.log"),
            "-w",
            "start",
        ]
    )
    if start.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        return f"pg_ctl start failed: {start.stderr[-300:]}"
    created = _as_postgres(
        [str(binaries / "createdb"), "-h", "127.0.0.1", "-p", str(port), "-U", "postgres", "unscheduled_test"]
    )
    if created.returncode != 0:
        _as_postgres([str(binaries / "pg_ctl"), "-D", str(data), "-m", "immediate", "stop"])
        shutil.rmtree(tmp, ignore_errors=True)
        return f"createdb failed: {created.stderr[-300:]}"
    return f"postgresql+psycopg://postgres@127.0.0.1:{port}/unscheduled_test", data, tmp


def _docker_answers() -> bool:
    try:
        import docker

        client = docker.from_env(timeout=5)
        client.ping()
        return True
    except Exception:
        return False


_STATE: dict[str, Any] = {}


def _stop() -> None:
    stop = _STATE.pop("stop", None)
    if stop is not None:
        stop()


def database_url() -> str:
    """One Postgres per test process, whichever test package asks first; stopped at exit."""
    if "url" in _STATE:
        return str(_STATE["url"])
    if "reason" in _STATE:
        _skip(str(_STATE["reason"]))
    explicit = os.environ.get(URL_VARIABLE, "").strip()
    if explicit:
        _STATE["url"] = explicit.replace("postgresql://", "postgresql+psycopg://", 1)
        return str(_STATE["url"])
    local = _local_cluster()
    if not isinstance(local, str):
        url, data, tmp = local

        def stop_local() -> None:
            binaries = pg_bin()
            if binaries is not None:
                _as_postgres([str(binaries / "pg_ctl"), "-D", str(data), "-m", "immediate", "stop"])
            shutil.rmtree(tmp, ignore_errors=True)

        _STATE.update(url=url, stop=stop_local)
        atexit.register(_stop)
        return url
    if _docker_answers():
        from testcontainers.postgres import PostgresContainer

        container = PostgresContainer("postgres:16-bookworm", driver="psycopg")
        container.start()
        _STATE.update(url=container.get_connection_url(), stop=container.stop)
        atexit.register(_stop)
        return str(_STATE["url"])
    _STATE["reason"] = f"{URL_VARIABLE} is not set, {local}, and no Docker daemon answers for testcontainers"
    _skip(str(_STATE["reason"]))
    raise AssertionError("unreachable")


@pytest.fixture(scope="session")
def postgres_url() -> str:
    return database_url()


def plain(url: str) -> str:
    """The libpq form of a SQLAlchemy URL, for a psycopg connection opened by hand."""
    return url.replace("postgresql+psycopg://", "postgresql://", 1)
