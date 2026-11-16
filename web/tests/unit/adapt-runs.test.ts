import { describe, expect, it } from "vitest";
import { GRAPH_ORDER, toRun, toRunList, toSearch } from "@/lib/api/adapt";
import { API_RUNS, API_RUN_DECIDED, API_RUN_EARLY, API_RUN_PLAN_APPROVED, API_RUN_WAITING, API_SEARCH } from "@/lib/fixtures/runs";

// FIXTURE: every input below was cut from a real answer of the API over its invented fixture data
// (lib/fixtures/runs.ts, scripts/cut_run_fixtures.py); none is data.

describe("a run at its first interrupt", () => {
  const run = toRun(API_RUN_WAITING);

  it("names the draft that waits by its kind and hash", () => {
    expect(run.status).toBe("waiting");
    expect(run.waiting).toEqual({ kind: "plan", sha256: API_RUN_WAITING.waiting_for?.[0]?.sha256 });
    expect(run.drafts.map((d) => [d.kind, d.status])).toEqual([["plan", "waiting"]]);
  });

  it("keeps every claim with its citations and its check", () => {
    const plan = run.drafts[0];
    expect(plan.claims.length).toBe(plan.claimsDrafted - plan.claimsRemoved);
    const fixed = plan.claims.find((c) => c.field === "fixed_version");
    expect(fixed?.value).toBe("1.2.1");
    expect(fixed?.citations[0]).toMatchObject({ source: "ghsa:GHSA-fx01-0001-aaaa", section: "affected" });
    expect(plan.claims.every((c) => c.failures.length === 0)).toBe(true);
    expect(plan.fields).toContainEqual({ label: "Fixed in", value: "1.2.1" });
    expect(plan.steps.length).toBeGreaterThan(0);
  });

  it("orders the nodes as the graph runs them, and reads what the run read", () => {
    const order = run.nodes.map((n) => (GRAPH_ORDER as readonly string[]).indexOf(n.name));
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(run.nodes.find((n) => n.name === "plan")?.calls).toBe(1);
    expect(run.facts.product).toBe("go-edge-service");
    expect(run.facts.kev?.date_added).toBe("2021-12-10");
    expect(Array.isArray(run.facts.evidence)).toBe(true);
    expect(run.untrusted).toContain("not an instruction");
  });
});

describe("a run that moved on", () => {
  it("after the plan's approval, the warning waits and the plan is approved", () => {
    const run = toRun(API_RUN_PLAN_APPROVED);
    expect(run.waiting?.kind).toBe("warning");
    expect(run.drafts.map((d) => d.status)).toEqual(["approved", "waiting"]);
    expect(run.drafts[1].fields.find((f) => f.label === "Actively exploited")?.value).toBe("yes");
    expect(run.decisions).toHaveLength(1);
    expect(run.decisions[0]).toMatchObject({ kind: "plan", decision: "approve", token_ok: true });
  });

  it("decided, nothing waits and the warning is ready", () => {
    const run = toRun(API_RUN_DECIDED);
    expect(run.status).toBe("decided");
    expect(run.waiting).toBeNull();
    expect(run.drafts.map((d) => d.status)).toEqual(["approved", "ready"]);
  });

  it("a run before the KEV listing knows the fix and drafts no warning", () => {
    const run = toRun(API_RUN_EARLY);
    expect(run.facts.fixed.map((f) => f.version)).toEqual(["1.2.1"]);
    expect(run.facts.kev).toBeNull();
    expect(run.drafts.map((d) => d.kind)).toEqual(["plan"]);
  });
});

describe("the lists", () => {
  it("keeps the runs in the order the API gave them", () => {
    expect(toRunList(API_RUNS).runs.map((r) => r.run_id)).toEqual(API_RUNS.runs.map((r) => r.run_id));
  });

  it("marks every search hit as untrusted", () => {
    const found = toSearch(API_SEARCH);
    expect(found.results.length).toBe(API_SEARCH.results.length);
    expect(found.results.every((h) => h.untrusted)).toBe(true);
    expect(found.configuration).toBe("floor");
  });
});
