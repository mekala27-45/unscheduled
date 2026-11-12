"""Draw the seeded samples later phases need, from the development and shadow windows only.

    python scripts/draw_samples.py           # writes config/samples.yaml if it does not exist
    python scripts/draw_samples.py --check   # the file matches its own rule and the lake
    python scripts/draw_samples.py --redraw  # replace it (only before it is registered)

The rule: the population is every published CVE (rejected excluded) in the lake whose publication
falls in the development window (2024) or the shadow window (from 2026-04-15), never the test window.
Each window's CVE ids are sorted, then a PCG64 generator seeded with SEED draws without replacement
150 per window for the Phase 3 agent golden set (300) and, from what is left, 50 per window for the
judge calibration set (100). The two sets never share a CVE. Sorting first makes the draw the same on
any machine and under any PYTHONHASHSEED; the population digest says exactly what was drawn from.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

import numpy as np
import yaml
from unscheduled_core import paths
from unscheduled_core.hashing import sha256_text

SEED = 20261108
WINDOWS = ("development", "shadow")
SETS = (("agent_golden", 150), ("judge_calibration", 50))

HEADER = """\
# Seeded samples for later phases, drawn by scripts/draw_samples.py from the development and shadow
# windows only (never test). Registered with the criteria in evaluation/registration.json; a redraw
# after registration is a change request in DECISIONS.md. The rule, the seed and the digest of the
# population drawn from are below, so anyone can draw the same CVEs again from the same lake.
"""


def population(lake_file: Path) -> tuple[dict[str, list[str]], str]:
    import duckdb

    con = duckdb.connect(str(lake_file), read_only=True)
    try:
        con.execute("set TimeZone = 'UTC'").fetchall()
        cut = con.execute("select data_cut from config.lake_build").fetchall()[0][0]
        out: dict[str, list[str]] = {}
        for window in WINDOWS:
            ids = [
                str(r[0])
                for r in con.execute(
                    "select cve_id from gold.cve_current where split_window = ? and state = 'PUBLISHED' order by cve_id",
                    [window],
                ).fetchall()
            ]
            out[window] = ids
    finally:
        con.close()
    return out, cut.isoformat()


def draw(pop: dict[str, list[str]], seed: int = SEED) -> dict[str, list[str]]:
    rng = np.random.Generator(np.random.PCG64(seed))
    chosen: dict[str, list[str]] = {name: [] for name, _ in SETS}
    for window in WINDOWS:
        ids = sorted(pop[window])
        need = sum(n for _, n in SETS)
        if len(ids) < need:
            raise ValueError(
                f"the {window} window holds {len(ids)} CVEs, fewer than the {need} the samples need"
            )
        picked = rng.choice(len(ids), size=need, replace=False)
        start = 0
        for name, n in SETS:
            chosen[name].extend(ids[i] for i in picked[start : start + n])
            start += n
    return {name: sorted(v) for name, v in chosen.items()}


def document(pop: dict[str, list[str]], cut: str, sets: dict[str, list[str]]) -> dict[str, Any]:
    return {
        "drawn_by": "scripts/draw_samples.py",
        "seed": SEED,
        "rule": (
            "Every published CVE in the development window (2024) and the shadow window (from 2026-04-15), rejected "
            "excluded; each window's ids sorted; a PCG64 generator with the seed draws without replacement 150 per "
            "window for agent_golden and, from the rest, 50 per window for judge_calibration."
        ),
        "lake_data_cut": cut,
        "population": {
            window: {"cves": len(ids), "sha256_of_sorted_ids": sha256_text("\n".join(sorted(ids)))}
            for window, ids in pop.items()
        },
        "samples": {
            name: {"size": len(ids), "per_window": dict.fromkeys(WINDOWS, n), "cve_ids": ids}
            for (name, n), ids in zip(SETS, (sets[name] for name, _ in SETS), strict=True)
        },
    }


def check(doc: dict[str, Any], pop: dict[str, list[str]]) -> list[str]:
    problems: list[str] = []
    inside = {c for ids in pop.values() for c in ids}
    seen: set[str] = set()
    for name, n in SETS:
        ids = doc["samples"][name]["cve_ids"]
        if len(ids) != 2 * n:
            problems.append(f"{name} holds {len(ids)} CVEs, not {2 * n}")
        outside = [c for c in ids if c not in inside]
        if outside:
            problems.append(f"{name} holds CVEs outside the development and shadow windows: {outside[:5]}")
        shared = seen & set(ids)
        if shared:
            problems.append(f"{name} shares CVEs with another sample: {sorted(shared)[:5]}")
        seen |= set(ids)
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="check the file against its rule and the lake")
    parser.add_argument("--redraw", action="store_true", help="replace the file (only before registration)")
    args = parser.parse_args(argv)
    target = paths.config_dir() / "samples.yaml"
    pop, cut = population(paths.lake_file())
    if args.check:
        doc = yaml.safe_load(target.read_text(encoding="utf-8"))
        problems = check(doc, pop)
        for p in problems:
            print(f"samples: {p}")
        print("samples: the file matches its rule" if not problems else "samples: check failed")
        return 1 if problems else 0
    if target.exists() and not args.redraw:
        print("samples: config/samples.yaml exists and may be registered; pass --redraw to replace it")
        return 1
    doc = document(pop, cut, draw(pop))
    problems = check(doc, pop)
    if problems:
        raise SystemExit("samples: the draw broke its own rule: " + "; ".join(problems))
    body = yaml.safe_dump(doc, sort_keys=False, width=100, allow_unicode=False)
    target.write_text(HEADER + body, encoding="utf-8")
    sizes = {name: s["size"] for name, s in doc["samples"].items()}
    print(f"samples: {sizes} from {doc['population']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
