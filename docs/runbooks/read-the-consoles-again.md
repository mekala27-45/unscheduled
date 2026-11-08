# Read the consoles again

scripts/probe_platform.py copies data/console_readings.yaml beside its live measurements and
refuses a reading more than thirty days old, so the plan limits a deploy step trusts are never
stale. When it refuses, read the consoles again.

1. Neon console, project unscheduled: the plan and its per project limits (Billing), the Postgres
   version, the default compute, the history retention, the storage used and the branch count
   (project overview).
2. Vercel, projects unscheduled-api and unscheduled: the plan, the domains, and the names (never
   the values) of the environment variables.
3. GitHub, repository settings, Actions: which actions are allowed, the default token permission,
   and whether Actions may create and approve pull requests.
4. Update data/console_readings.yaml with what each page shows and set read_on to the day.
5. Run `python scripts/probe_platform.py`, then commit both files in one commit.

A reading that changed a limit the build depends on (the Neon storage per project, the Vercel plan)
also needs a DECISIONS.md entry and, if it touches config/budgets.yaml, a change request, since
that file is registered.
