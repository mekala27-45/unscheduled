"""Write and run the three dead end notebooks, keeping what each first attempt got wrong.

    python scripts/make_notebooks.py        # notebooks/01_..., 02_..., 03_... with their outputs

Each notebook is written cell by cell from this file and run here, in one namespace per notebook,
against the lake file (read only) and the committed results; every output in the .ipynb is what the
cell printed or returned when it ran. No kernel is started: a code cell is executed with exec, its
printed lines and the value of its last expression are kept as the cell's output, the way Jupyter
shows them. The notebooks are records, so CI does not run them again.
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

OUT = ROOT / "notebooks"
Cell = tuple[str, str]

SETUP = """import duckdb
import polars as pl

pl.Config.set_tbl_rows(12)
pl.Config.set_tbl_width_chars(110)
con = duckdb.connect("data/lake/unscheduled.duckdb", read_only=True)
con.execute("set TimeZone = 'UTC'").fetchall()
cut = con.execute("select data_cut from config.lake_build").fetchall()[0][0]
print("lake cut at", cut)"""

NB01: list[Cell] = [
    (
        "markdown",
        "# 01, the first backlog chart\n\n"
        "The first chart of Q1 divided the CVEs the NVD analyzed within 30 days by every CVE published "
        "that month. Rejected CVEs were in the denominator, and the NVD never analyzes a rejected CVE, "
        "so every rejection read as a CVE the NVD skipped. This notebook shows how much that moved the "
        "line, and why the registered Q1 leaves rejected CVEs out.",
    ),
    ("code", SETUP),
    (
        "code",
        """first = con.sql('''
    select published_month as month,
           count(*) as cves,
           count(*) filter (where state = 'REJECTED') as rejected,
           avg(case when first_analysis_at is not null
                     and first_analysis_at <= published + interval 30 day then 1 else 0 end) as share_first
    from gold.cve_current
    where published >= timestamptz '2020-01-01 00:00:00+00'
      and published + interval 30 day <= $cut
    group by all order by month
''', params={"cut": cut}).pl()
first.tail(6)""",
    ),
    (
        "markdown",
        "The fix: rejected CVEs out of the population, as the registered plan states it, and a CVE "
        "judged at 30 days only once 30 days have passed (the censoring the mart applies).",
    ),
    (
        "code",
        """fixed = con.sql('''
    select published_month as month, avg(cast(analyzed_30d as integer)) as share_fixed
    from gold.mart_backlog_q1
    group by all order by month
''').pl()
both = first.join(fixed, on="month").with_columns(
    (pl.col("share_fixed") - pl.col("share_first")).alias("moved_by")
)
both.select("month", "rejected", "share_first", "share_fixed", "moved_by").tail(6)""",
    ),
    (
        "code",
        """worst = both.sort("moved_by", descending=True).head(3)
print("months the rejected CVEs pulled down most:")
for row in worst.iter_rows(named=True):
    print(f"  {row['month']}: {row['rejected']} rejected, {row['share_first']:.1%} first, {row['share_fixed']:.1%} fixed")""",
    ),
    (
        "markdown",
        "What changed in the build: dbt/models/marts/mart_backlog_q1.sql keeps state <> 'REJECTED' in "
        "its population, and the Q1 departure note in results/backlog/q1.json says why.",
    ),
]

NB02: list[Cell] = [
    (
        "markdown",
        "# 02, kappa on everything\n\n"
        "The first agreement between filer and NVD severity was a kappa over every CVE with either "
        "score, with a missing score counted as its own band. Most of those CVEs have only one of the "
        "two scores, so the kappa mostly measured who scored, not whether the scores agree. The "
        "registered Q4 restricts to the CVEs both scored.",
    ),
    ("code", SETUP),
    (
        "code",
        """from unscheduled_analysis.stats import cohen_kappa

bands = ["None", "Low", "Medium", "High", "Critical"]
code = {b.upper(): i for i, b in enumerate(bands)}
frame = con.sql('''
    select upper(coalesce(filer_cvss31_band, 'NONE')) as filer,
           upper(coalesce(nvd_cvss31_band, 'NONE')) as nvd
    from gold.cve_current
    where state <> 'REJECTED' and (filer_cvss31_band is not null or nvd_cvss31_band is not null)
''').pl()
f = [code.get(x, 0) for x in frame["filer"]]
n = [code.get(x, 0) for x in frame["nvd"]]
print(f"{frame.height:,} CVEs with either score")
print("weighted kappa on everything:", round(cohen_kappa(f, n, k=5, weights="quadratic"), 3))""",
    ),
    (
        "code",
        """both = frame.filter((pl.col("filer") != "NONE") & (pl.col("nvd") != "NONE"))
f2 = [code[x] for x in both["filer"]]
n2 = [code[x] for x in both["nvd"]]
print(f"{both.height:,} CVEs both scored")
print("weighted kappa where both scored:", round(cohen_kappa(f2, n2, k=5, weights="quadratic"), 3))
print("one side missing:", f"{(frame.height - both.height) / frame.height:.1%} of the first population")""",
    ),
    (
        "markdown",
        "A missing score was coded as the band None, the same code as a score of 0.0, so the first "
        "kappa was mostly a measure of which CVEs had two scores. The registered Q4 also leaves out the "
        "test window, which is held for Phase 2, so its weighted kappa on the band (report/backlog.md) "
        "is computed on fewer CVEs than the both scored row above.",
    ),
    (
        "markdown",
        "What changed in the build: Q4 (packages/analysis questions/q4.py and gold.mart_filer_vs_nvd) "
        "takes the CVEs scored with CVSS 3.1 by both the filer and the NVD, reports a kappa per metric "
        "and a weighted kappa on the band, each with a cluster bootstrap interval by filer.",
    ),
]

NB03: list[Cell] = [
    (
        "markdown",
        "# 03, the matcher without schemes\n\n"
        "The first matcher compared versions as text. As text, 4.10.0 comes before 4.9.0, so a "
        "component above a fix looked affected and a component below a limit looked safe. This "
        "notebook runs both comparisons over every single interval range the committed exposure "
        "matched, and lists the findings the text comparison would have lost.",
    ),
    (
        "code",
        """import json
import re
from pathlib import Path

from univers.version_range import VersionRange

findings = []
for name in ("findings_pin.json", "findings_today.json"):
    data = json.loads(Path(f"results/exposure/{name}").read_text())
    for block in data["products"].values():
        findings.extend(block["findings"])
pairs = {
    (m["matched_range"], f["version"])
    for f in findings
    for m in f["matches"]
    if (m.get("matched_range") or "").startswith("vers:")
}
print(len(findings), "findings,", len(pairs), "distinct range and version pairs")""",
    ),
    (
        "code",
        """OPS = re.compile(r"^(>=|<=|<|>)(.*)$")


def simple(vers: str) -> list[tuple[str, str]] | None:
    # One interval at most: a lower bound, an upper bound or both. A range of several intervals
    # needs the vers ordering rules on top of the comparison, so it is left out of this check.
    parts = [OPS.match(x) for x in vers.split("/", 1)[1].split("|")]
    if len(parts) > 2 or any(m is None for m in parts):
        return None
    ops = [m.group(1) for m in parts]
    if len(ops) == 2 and not (ops[0].startswith(">") and ops[1].startswith("<")):
        return None
    return [(m.group(1), m.group(2)) for m in parts]


def as_text(constraints: list[tuple[str, str]], version: str) -> bool:
    # The first matcher: the same interval, every bound compared as plain text.
    test = {"<": str.__lt__, "<=": str.__le__, ">": str.__gt__, ">=": str.__ge__}
    return all(test[op](version, bound) for op, bound in constraints)


def by_scheme(vers: str, version: str) -> bool:
    r = VersionRange.from_string(vers)
    return r.version_class(version) in r


rows = []
for v, ver in sorted(pairs):
    c = simple(v)
    if c is None:
        continue
    rows.append((v, ver, as_text(c, ver), by_scheme(v, ver)))
missed = [r for r in rows if r[3] and not r[2]]
print(f"{len(rows)} pairs with a single interval (of {len(pairs)}); text comparison misses {len(missed)}")
for v, ver, _, _ in missed[:8]:
    print(f"  {ver} against {v}")""",
    ),
    (
        "markdown",
        "Every pair above is a finding the scheme aware matcher made that the text comparison would "
        "have dropped, because as text 0.17.8 sorts after 0.17.12 and 0.10.0 before 0.8.0.",
    ),
    (
        "markdown",
        "What changed in the build: packages/match/src/unscheduled_match/ranges.py parses each "
        "version with the class of its ecosystem (univers), and the exposure step runs osv-scanner "
        "on the same SBOMs, so a disagreement between the two cannot pass unexplained "
        "(results/exposure/disagreements.json).",
    ),
]


def run_cells(cells: list[Cell]) -> list[dict[str, Any]]:
    namespace: dict[str, Any] = {"__name__": "__notebook__"}
    out: list[dict[str, Any]] = []
    count = 0
    for kind, source in cells:
        if kind == "markdown":
            out.append({"cell_type": "markdown", "metadata": {}, "source": source})
            continue
        count += 1
        tree = ast.parse(source)
        tail = tree.body[-1] if tree.body else None
        last = tail.value if isinstance(tail, ast.Expr) else None
        if last is not None:
            tree.body.pop()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            exec(compile(tree, f"<cell {count}>", "exec"), namespace)
            value = None
            if last is not None:
                value = eval(compile(ast.Expression(last), f"<cell {count}>", "eval"), namespace)
        outputs: list[dict[str, Any]] = []
        if buffer.getvalue():
            outputs.append({"output_type": "stream", "name": "stdout", "text": buffer.getvalue()})
        if value is not None:
            outputs.append(
                {
                    "output_type": "execute_result",
                    "execution_count": count,
                    "metadata": {},
                    "data": {"text/plain": repr(value)},
                }
            )
        out.append(
            {
                "cell_type": "code",
                "execution_count": count,
                "metadata": {},
                "outputs": outputs,
                "source": source,
            }
        )
    return out


def write(name: str, cells: list[Cell]) -> Path:
    notebook = {
        "cells": run_cells(cells),
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "version": "3.12"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{name}.ipynb"
    path.write_text(json.dumps(notebook, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def main() -> int:
    import os

    os.chdir(ROOT)
    for name, cells in (
        ("01_the_first_backlog_chart", NB01),
        ("02_kappa_on_everything", NB02),
        ("03_the_matcher_without_schemes", NB03),
    ):
        print(f"notebooks: wrote {write(name, cells).relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
