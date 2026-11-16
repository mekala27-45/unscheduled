"""A language model only inside the agent, and model libraries only where a phase uses them.

Phase 1 refused every model library. Phase 2 allowed the deep learning and embedding libraries under
packages/models and kaggle/, where the models are trained, and the ONNX runtime under packages/models
and packages/api, where they are served. Phase 3 adds three places and nothing else:

- packages/agent may import the model provider clients and the agent graph, and its compare folder,
  which the API never imports, the two other agent frameworks of step 13;
- packages/mcp may import the MCP SDK;
- packages/retrieval may import the embedding and ONNX libraries it builds its index and its
  reranker with.

The models, the matcher, the lake, the API and the scripts never import a provider client, so a
language model can reach only what the agent hands it, and no field that code decides. A few
libraries stay refused everywhere: anthropic and vllm (no free tier, no GPU) and litellm and the full
langchain (more than the agent needs).
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Refused in every file.
EVERYWHERE = ("vllm", "anthropic", "litellm", "langchain")
# Allowed only under these folders, relative to the repository root. A dotted name covers the
# module and everything under it, so google.genai is scoped while the rest of google is not.
SCOPED: dict[str, tuple[str, ...]] = {
    "torch": ("packages/models", "kaggle", "packages/retrieval"),
    "transformers": ("packages/models", "kaggle", "packages/retrieval"),
    "sentence_transformers": ("packages/models", "kaggle", "packages/retrieval"),
    "optimum": ("packages/models", "kaggle", "packages/retrieval"),
    "onnxruntime": ("packages/models", "packages/api", "packages/retrieval"),
    "openai": ("packages/agent",),
    "google.genai": ("packages/agent",),
    "groq": ("packages/agent",),
    "langgraph": ("packages/agent",),
    "langchain_core": ("packages/agent",),
    "agents": ("packages/agent/compare",),
    "google.adk": ("packages/agent/compare",),
    "mcp": ("packages/mcp",),
}
SCANNED = ("packages", "scripts", "kaggle")
IMPORT = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][\w.]*)", re.M)


def imported(text: str) -> list[str]:
    """Every module a file imports, with from X import Y read as both X and X.Y, so that
    from google import genai is caught like import google.genai. A file that does not parse is
    read line by line instead."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return IMPORT.findall(text)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.append(node.module)
            found.extend(f"{node.module}.{alias.name}" for alias in node.names)
    return found


def _inside(where: str, folder: str) -> bool:
    return where == folder or where.startswith(folder + "/")


def refused_imports(text: str, where: str = "") -> list[str]:
    """The imports in a file that its place in the repository does not allow."""
    found = []
    for module in imported(text):
        top = module.split(".")[0]
        if top in EVERYWHERE or module in EVERYWHERE:
            found.append(module)
            continue
        for scoped, folders in SCOPED.items():
            if (module == scoped or module.startswith(scoped + ".")) and not any(
                _inside(where, folder) for folder in folders
            ):
                found.append(module)
                break
    return found


def check(root: Path, files: list[Path] | None = None) -> int:
    if files is None:
        files = sorted(
            p
            for base in SCANNED
            if (root / base).exists()
            for p in (root / base).rglob("*.py")
            if ".venv" not in p.parts and p.name != Path(__file__).name
        )
    if not files:
        raise ValueError("the model gate found no files to scan")
    problems = []
    for p in files:
        if not p.exists():
            continue
        where = p.resolve().relative_to(root.resolve()).as_posix() if p.is_absolute() else p.as_posix()
        found = refused_imports(p.read_text(encoding="utf-8"), where)
        if found:
            problems.append(f"{where}: {sorted(set(found))}")
    if problems:
        raise ValueError(
            "model gate failed (a provider client or agent framework only in packages/agent and "
            "packages/mcp; model libraries only where a phase trains, serves or retrieves):\n"
            + "\n".join(problems)
        )
    return len(files)


if __name__ == "__main__":
    count = check(Path(__file__).resolve().parents[1])
    print(
        f"model gate: {count} files, provider clients only in the agent, model libraries only where allowed"
    )
