"""Fail on anything that looks like a credential in a tracked file or in the diff being pushed.

Nobody types a secret in this build: the database connection reaches Vercel through the Neon
integration and GitHub Actions holds no credential. This gate keeps it that way. It refuses to
report a pass when it found nothing to scan.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts._files import authored_files

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("postgres url with a password", re.compile(r"postgres(?:ql)?://[^\s:/@]+:[^\s@/]{6,}@[^\s/]+")),
    ("github token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("github fine grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("aws access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google api key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("vercel or neon style api key", re.compile(r"\b(?:napi|vcp)_[A-Za-z0-9]{24,}\b")),
    (
        "generic assigned secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\x27\x22][A-Za-z0-9/+_\-]{20,}[\x27\x22]"
        ),
    ),
)


def find_secrets(text: str) -> list[str]:
    return [name for name, pattern in PATTERNS if pattern.search(text)]


def check(root: Path, files: list[Path] | None = None) -> int:
    targets = files if files is not None else authored_files(root, include_data=True)
    targets = [p for p in targets if p.name != Path(__file__).name]
    if not targets:
        raise ValueError("the secret gate found no files to scan")
    problems: list[str] = []
    for path in targets:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for name in find_secrets(text):
            problems.append(f"{path.relative_to(root)}: {name}")
    if problems:
        raise ValueError("secret gate failed:\n" + "\n".join(problems[:50]))
    return len(targets)


if __name__ == "__main__":
    count = check(Path(__file__).resolve().parents[1])
    print(f"secret gate: {count} files, nothing that looks like a credential")
