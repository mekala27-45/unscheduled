"""Answer the backlog questions Q1 to Q6 and Q8 from the lake, as evaluation/phase1_plan.yaml states them.

    python scripts/run_analysis.py              # every question
    python scripts/run_analysis.py --only Q1 Q4 # some of them

Reads data/lake/unscheduled.duckdb read only; writes results/backlog/q<n>.json and the manifest part
results/parts/backlog.json. Q7 comes from the exposure build. Any departure from the plan forced by
the data is written into the question's file under `departure`.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from unscheduled_analysis import lake, report
from unscheduled_analysis.questions import q1, q2, q3, q4, q5, q6, q8
from unscheduled_core import paths

QUESTIONS = {"Q1": q1.run, "Q2": q2.run, "Q3": q3.run, "Q4": q4.run, "Q5": q5.run, "Q6": q6.run, "Q8": q8.run}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", nargs="*", default=None, help="question ids to run")
    args = parser.parse_args(argv)
    chosen = [q.upper() for q in (args.only or list(QUESTIONS))]
    plan = lake.plan()
    con = lake.connect()
    try:
        cut = lake.data_cut(con).isoformat()
        results = []
        for qid in chosen:
            started = time.monotonic()
            result = QUESTIONS[qid](con, plan[qid], cut)
            results.append(result)
            print(
                f"{qid}: {len(result.values)} values, {len(result.tables)} tables, {len(result.departures)} departures, {time.monotonic() - started:.1f}s"
            )
    finally:
        con.close()
    results_dir = paths.results_dir()
    if args.only:
        for r in results:
            r.write(results_dir / "backlog")
        print("partial run: question files written, manifest part left as it was")
        return 0
    report.write(results, results_dir / "backlog", results_dir / "parts" / "backlog.json", cut[:10])
    return 0


if __name__ == "__main__":
    sys.exit(main())
