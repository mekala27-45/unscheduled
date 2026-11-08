"""The statement on every surface: the documents and every prerendered page of the built site.

API response bodies are covered by tests/api, and every live route by the Playwright suite.
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from unscheduled_core.statements import contains_statement

DOCUMENTS = (
    "README.md",
    "RESULTS.md",
    "data/PROVENANCE.md",
    "customer/README.md",
)
GLOBS = ("report/*.md", "web/.next/server/app/**/*.html")


def surfaces(root: Path) -> list[Path]:
    found = [root / doc for doc in DOCUMENTS if (root / doc).exists()]
    for pattern in GLOBS:
        # _global-error.html is the fallback Next.js prerenders itself; app/global-error.tsx, which
        # carries the statement, replaces it at runtime, so the prerendered shell is not a surface.
        found.extend(
            sorted(
                p
                for p in root.glob(pattern)
                if "node_modules" not in p.parts and not p.name.startswith("_global-error")
            )
        )
    return found


def check(root: Path, files: list[Path] | None = None) -> int:
    targets = files if files is not None else surfaces(root)
    targets = list(dict.fromkeys(targets))
    if not targets:
        raise ValueError("the statement gate found no surfaces to check")
    missing = [str(p.relative_to(root)) for p in targets if not contains_statement(_visible_text(p))]
    if missing:
        raise ValueError("these surfaces are missing the statement:\n" + "\n".join(missing))
    return len(targets)


def _visible_text(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".html":
        import html
        import re

        text = re.sub(r"<script.*?</script>", " ", text, flags=re.S)
        text = re.sub(r"<style.*?</style>", " ", text, flags=re.S)
        text = re.sub(r"<[^>]+>", " ", text)
        text = html.unescape(text)
    return text


if __name__ == "__main__":
    count = check(Path(__file__).resolve().parents[1])
    print(f"statement gate: the statement is present on {count} surfaces")
