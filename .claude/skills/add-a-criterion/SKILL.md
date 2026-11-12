---
name: add-a-criterion
description: Change or add an acceptance criterion of unscheduled through a dated change request with both verdicts, never a silent edit. Use when a threshold, population, split or evidence file in config/criteria.yaml needs to change.
---

# Add or change a criterion

config/criteria.yaml, splits.yaml, budgets.yaml, labels.yaml, samples.yaml and
evaluation/phase1_plan.yaml are registered: `make gates` fails if any of them changes after its hash
(evaluation/registration_plan.json and registration.json). A change is therefore a change request.

1. **Write the request** in DECISIONS.md under today's date: the criterion, the old and the new text,
   why (with the source and the date read), and who asked.
2. **Compute both verdicts.** Run the evidence under the old terms and the new ones and write both
   into the entry, so a reader sees what the change would have flipped.
3. **Register again.** Move the old registration files to evaluation/registrations/<date>/, edit the
   file, run `uv run python scripts/register.py plan` (and `data` if a data file changed), and
   commit the edit, the new registration and the DECISIONS entry together as
   `chore(plan): change request <id>`.
4. **Render.** `uv run python scripts/build_manifest.py` and
   `uv run python scripts/check_published_numbers.py --write`, so report/criteria.md and the
   console's criteria page show the new terms with the change request beside them.

Never change a threshold after seeing a result without step 2. A request made after the evidence is
in is reported as such.
