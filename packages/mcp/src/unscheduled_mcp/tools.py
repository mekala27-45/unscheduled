"""The tools the MCP server serves, and the one dispatcher every transport calls.

Three tools, all of them reads or a draft: search_advisories (the corpus as known at a time),
start_triage (a run of the triage graph to its approval interrupts) and read_run (the drafts of a
run and their status). No tool approves, applies, files or changes a recorded value: a person
approves a draft in the console with the approver's token, and a request for any other tool is
refused by name.

Every argument is checked before a tool runs, against a schema that accepts no other field: a CVE
id is the CVE id pattern and nothing else, a run id is 32 hex characters, a query is at most 2,000
characters, and an as-of time is a date that has already ended. Free text reaches the backend only
as a bound parameter, so a query that reads like SQL is searched for as text.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

MAX_QUERY = 2_000
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
RUN_ID = re.compile(r"^[0-9a-f]{32}$")


class Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _past(value: date) -> date:
    if datetime.combine(value, time.max, tzinfo=UTC) > datetime.now(UTC):
        raise ValueError("an as-of date must be a day that has already ended")
    return value


class Search(Arguments):
    query: str = Field(min_length=1, max_length=MAX_QUERY)
    as_of: date

    @field_validator("as_of")
    @classmethod
    def ended(cls, value: date) -> date:
        return _past(value)


class StartTriage(Arguments):
    cve_id: str
    as_of: date | None = None

    @field_validator("cve_id")
    @classmethod
    def cve(cls, value: str) -> str:
        if not CVE_ID.match(value):
            raise ValueError("a CVE id is CVE-, a year, a dash and four to seven digits")
        return value

    @field_validator("as_of")
    @classmethod
    def ended(cls, value: date | None) -> date | None:
        return _past(value) if value is not None else None


class ReadRun(Arguments):
    run_id: str

    @field_validator("run_id")
    @classmethod
    def run(cls, value: str) -> str:
        if not RUN_ID.match(value):
            raise ValueError("a run id is 32 hexadecimal characters")
        return value


class Backend(Protocol):
    def search(self, query: str, as_of: date) -> list[dict[str, Any]]: ...

    def start_triage(self, cve_id: str, as_of: date | None) -> dict[str, Any]: ...

    def read_run(self, run_id: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    arguments: type[Arguments]
    call: Callable[[Backend, Any], Any]


TOOLS: dict[str, Tool] = {
    "search_advisories": Tool(
        "search_advisories",
        "Search the advisory corpus as it was known at the end of a past day; returns chunks with their documents and known_from.",
        Search,
        lambda b, a: b.search(a.query, a.as_of),
    ),
    "start_triage": Tool(
        "start_triage",
        "Run the triage graph for one CVE as of a past day to its approval interrupts; returns the run id and the drafts waiting for a person.",
        StartTriage,
        lambda b, a: b.start_triage(a.cve_id, a.as_of),
    ),
    "read_run": Tool(
        "read_run",
        "Read one run: its drafts, the verifier's results and each draft's status.",
        ReadRun,
        lambda b, a: b.read_run(a.run_id),
    ),
}
# Named here so a refusal says what the tool would have done; none of them exists.
NEVER = {
    "approve": "approving is a person's decision, made in the console with the approver's token",
    "apply_plan": "nothing applies a plan; a person acts on an approved one",
    "file_warning": "nothing files a warning; a person files a ready one on the ENISA platform",
    "set_severity": "no tool changes a recorded value",
}


@dataclass
class Result:
    ok: bool
    content: Any = None
    refused: str | None = None
    tool: str = ""
    errors: list[str] = field(default_factory=list)


def schema(tool: Tool) -> dict[str, Any]:
    return tool.arguments.model_json_schema()


def dispatch(name: str, arguments: dict[str, Any], backend: Backend) -> Result:
    """Check a request and run its tool, or refuse it and say why; the backend sees only checked values."""
    if name in NEVER:
        return Result(False, refused=f"there is no tool {name}: {NEVER[name]}", tool=name)
    tool = TOOLS.get(name)
    if tool is None:
        return Result(False, refused=f"there is no tool {name}", tool=name)
    try:
        checked = tool.arguments.model_validate(arguments)
    except ValidationError as err:
        problems = [
            f"{'.'.join(str(x) for x in e['loc']) or 'arguments'}: {e['msg']}" for e in err.errors()[:5]
        ]
        return Result(
            False, refused="the arguments do not match the tool's schema", tool=name, errors=problems
        )
    return Result(True, content=tool.call(backend, checked), tool=name)
