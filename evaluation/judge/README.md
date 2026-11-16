# The judge's labels

The judge of Phase 3 (evaluation/phase3_plan.yaml, judge) is a model that marks a draft usable or
not. It is calibrated against forty development drafts that Ajay labels in the console, and it never
gates a criterion.

- drafts.json: the forty drafts, half from the no model floor and half from the model
  configurations, drawn by seed from the development evals by scripts/draw_judge_drafts.py. Each
  has its id, kind, CVE, run time, hash and the draft itself, and nothing that says which
  configuration wrote it. GET /v1/labels serves them, and POST /v1/labels records a label with the
  approver's token.

Which configuration wrote each draft is in evaluation/judge_key.json, outside this folder, so the
API image that serves the drafts never holds it; only the scorer opens it, after the labels are in.
Neither file exists until the development evals of step 12 have run.
