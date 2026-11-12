"""Write CHANGELOG.md from the conventional commits, newest release first.

    python scripts/changelog.py                # the commits since the newest tag, as Unreleased
    python scripts/changelog.py --next v0.1.0  # the same section, titled with the tag it will carry

Each section holds the commits between two version tags, grouped by type in a fixed order, each with
its subject as written and its short hash. Nothing in the file is typed by hand: it is the history up
to the commit before the one that adds the file, which is run again before each tag.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "CHANGELOG.md"
SUBJECT = re.compile(r"^(?P<type>[a-z]+)(\((?P<scope>[a-z0-9 ,_/-]+)\))?!?: (?P<text>.+)$")
GROUPS: tuple[tuple[str, str], ...] = (
    ("feat", "Added"),
    ("fix", "Fixed"),
    ("perf", "Faster"),
    ("refactor", "Changed inside"),
    ("docs", "Documents"),
    ("test", "Tests"),
    ("ci", "Continuous integration"),
    ("build", "Build"),
    ("chore", "Chores"),
)
VERSION_TAG = re.compile(r"^v\d+\.\d+\.\d+$")


@dataclass(frozen=True)
class Commit:
    sha: str
    subject: str


@dataclass(frozen=True)
class Section:
    title: str
    date: str | None
    commits: tuple[Commit, ...]


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def version_tags() -> list[str]:
    """Version tags, newest first."""
    return [t for t in _git("tag", "--list", "v*", "--sort=-v:refname").splitlines() if VERSION_TAG.match(t)]


def commits_between(start: str | None, end: str) -> tuple[Commit, ...]:
    span = f"{start}..{end}" if start else end
    out = _git("log", "--no-merges", "--format=%h%x09%s", span)
    return tuple(Commit(*line.split("\t", 1)) for line in out.splitlines() if "\t" in line)


def sections(next_tag: str | None) -> list[Section]:
    tags = version_tags()
    found: list[Section] = []
    head = commits_between(tags[0] if tags else None, "HEAD")
    if head:
        found.append(Section(next_tag or "Unreleased", None, head))
    for i, tag in enumerate(tags):
        older = tags[i + 1] if i + 1 < len(tags) else None
        date = _git("log", "-1", "--format=%cs", tag).strip()
        found.append(Section(tag, date, commits_between(older, tag)))
    return found


def render(found: Sequence[Section]) -> str:
    lines = [
        "# Changelog",
        "",
        "Every version tag with the conventional commits it carries, newest first, written by",
        "scripts/changelog.py from the history before each tag. A subject reads as it was committed.",
        "",
    ]
    for section in found:
        lines.append(f"## {section.title}" + (f", {section.date}" if section.date else ""))
        lines.append("")
        grouped: dict[str, list[str]] = {}
        other: list[str] = []
        for commit in section.commits:
            match = SUBJECT.match(commit.subject)
            if match is None:
                other.append(f"- {commit.subject} ({commit.sha})")
                continue
            scope = match.group("scope")
            text = f"{scope}: {match.group('text')}" if scope else match.group("text")
            grouped.setdefault(match.group("type"), []).append(f"- {text} ({commit.sha})")
        for kind, heading in GROUPS:
            if kind in grouped:
                lines.extend([f"### {heading}", "", *grouped.pop(kind), ""])
        rest = [line for kind in sorted(grouped) for line in grouped[kind]] + other
        if rest:
            lines.extend(["### Other", "", *rest, ""])
    return "\n".join(lines).rstrip("\n") + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--next", dest="next_tag", help="title the untagged commits with this tag")
    args = parser.parse_args(argv)
    if args.next_tag and not VERSION_TAG.match(args.next_tag):
        parser.error("--next takes a version tag such as v0.1.0")
    OUT.write_text(render(sections(args.next_tag)), encoding="utf-8")
    print(f"changelog: wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
