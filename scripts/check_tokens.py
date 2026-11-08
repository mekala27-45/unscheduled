"""Fail if a color or a font family is written anywhere in web/ outside the token block.

Every color and every face on the site goes through a custom property defined in
web/styles/tokens.css (section 15). A hex value, an rgb, hsl, oklch, lab or color() function, or a
font family named in a stylesheet, a component or a Tailwind arbitrary value is a second source of
truth, so the gate refuses it. Static files in web/public (exported diagrams) and the palette data
the validator reads are outside the rule. The gate refuses to report a pass when it found nothing
to scan.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts._files import authored_files

TOKEN_FILE = Path("web/styles/tokens.css")
EXEMPT = {TOKEN_FILE, Path("web/theme/palette.json"), Path("web/lib/statement.ts")}
SUFFIXES = {".css", ".ts", ".tsx", ".js", ".mjs"}

HEX = re.compile(r"(?<=[:\s(,'\"`=\[])#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3,4})(?![\w-])")
FUNCTION = re.compile(r"(?<![\w-])(?:rgba?|hsla?|hwb|oklch|oklab|lab|lch|color)\(\s*[\d.]")
FONT_CSS = re.compile(r"font-family\s*:\s*(?!\s*(?:var\(|(?:inherit|initial|unset)\b))")
FONT_JS = re.compile(r"fontFamily\s*:\s*['\"`]")
RULES = (
    (HEX, "hex color"),
    (FUNCTION, "color function"),
    (FONT_CSS, "font family outside a token"),
    (FONT_JS, "font family outside a token"),
)


def find_literals(text: str) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        code = line.split("//", 1)[0] if not line.lstrip().startswith(("*", "/*")) else ""
        for pattern, name in RULES:
            if pattern.search(code):
                hits.append((number, name))
    return hits


def web_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in authored_files(root):
        rel = path.relative_to(root)
        if rel.parts[:1] != ("web",) or rel.parts[:2] == ("web", "public"):
            continue
        if rel in EXEMPT or path.suffix not in SUFFIXES:
            continue
        out.append(path)
    return out


def check(root: Path, files: list[Path] | None = None) -> int:
    targets = files if files is not None else web_files(root)
    if not targets:
        raise ValueError("the token gate found no files to scan")
    problems: list[str] = []
    for path in targets:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        for line, name in find_literals(text):
            problems.append(f"{path.relative_to(root)}:{line}: {name}")
    if problems:
        raise ValueError("token gate failed:\n" + "\n".join(problems[:60]))
    return len(targets)


if __name__ == "__main__":
    count = check(Path(__file__).resolve().parents[1])
    print(f"token gate: {count} web files, every color and face through a token")
