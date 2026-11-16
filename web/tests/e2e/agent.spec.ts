import { expect, test } from "@playwright/test";
import {
  API_APPROVAL_REFUSED,
  API_LABELS_OPEN,
  API_LABEL_KEPT,
  API_LABEL_REFUSED,
  API_RUNS,
  API_RUN_DECIDED,
  API_RUN_PLAN_APPROVED,
  API_RUN_WAITING,
} from "../../lib/fixtures/runs";
import { json, mockApi } from "./mock";

const RUN = API_RUN_WAITING.run_id;
/** A short stand in for the approver's token; the mock API only checks that it arrives in the header. */
const TEST_TOKEN = "test-token";

test.describe("the runs", () => {
  test("lists every run with its status, and starts one that opens at its first interrupt", async ({ page }) => {
    let sent: unknown = null;
    await mockApi(page, {
      "POST /v1/triage": (r) => {
        sent = r.request().postDataJSON();
        return json(r, API_RUN_WAITING);
      },
    });
    await page.goto("/app/runs");
    await expect(page.getByRole("region", { name: /Triage runs/ }).getByRole("row")).toHaveCount(API_RUNS.runs.length + 1);
    await expect(page.getByText("Waits for a person").first()).toBeVisible();
    await page.getByLabel("CVE").fill("cve-2099-0001");
    await page.getByLabel("As of (optional)").fill("2022-01-15");
    await page.getByRole("button", { name: "Start a run" }).click();
    await expect(page).toHaveURL(new RegExp(`/app/runs/${RUN}$`));
    expect(sent).toEqual({ cve_id: "CVE-2099-0001", as_of: "2022-01-15" });
  });

  test("refuses a string that is not a CVE id before sending it", async ({ page }) => {
    let sent = false;
    await mockApi(page, { "POST /v1/triage": (r) => ((sent = true), json(r, API_RUN_WAITING)) });
    await page.goto("/app/runs");
    await page.getByLabel("CVE").fill("log4shell");
    await page.getByRole("button", { name: "Start a run" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "A CVE id is CVE" })).toBeVisible();
    expect(sent).toBe(false);
  });

  test("an empty store says what belongs there", async ({ page }) => {
    await mockApi(page, { "GET /v1/runs": (r) => json(r, { ...API_RUNS, runs: [] }) });
    await page.goto("/app/runs");
    await expect(page.getByText("No run yet")).toBeVisible();
  });
});

test.describe("one run", () => {
  test("shows the graph, the drafts labelled as drafts, every claim with its check, and what waits", async ({ page }) => {
    await mockApi(page);
    await page.goto(`/app/runs/${RUN}`);
    await expect(page.getByRole("heading", { name: "Draft patch plan" })).toBeVisible();
    await expect(page.getByRole("region", { name: /claims of the plan/ })).toContainText("Holds in its source");
    await expect(page.getByRole("list", { name: /nodes of the triage graph/ })).toContainText("retrieve");
    await expect(page.getByText("not reached").first()).toBeVisible();
    await expect(page.getByRole("heading", { name: "What waits for a person" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Approve this draft" })).toBeDisabled();
    await expect(page.getByRole("note").filter({ hasText: "anyone can write" })).toBeVisible();
  });

  test("a decision sends the hash with the token in the header, then shows the next draft that waits", async ({ page }) => {
    let header: string | null = null;
    let body: Record<string, unknown> | null = null;
    await mockApi(page, {
      "POST /v1/approvals": (r) => {
        header = r.request().headers()["authorization"] ?? null;
        body = r.request().postDataJSON() as Record<string, unknown>;
        return json(r, API_RUN_PLAN_APPROVED);
      },
    });
    await page.goto(`/app/runs/${RUN}`);
    await page.getByLabel("Approver token").fill(TEST_TOKEN);
    await page.getByRole("button", { name: "Approve this draft" }).click();
    await expect(page.getByRole("heading", { name: "Draft early warning" })).toBeVisible();
    await expect(page.getByText("Approved by a person")).toBeVisible();
    expect(header).toBe(`Bearer ${TEST_TOKEN}`);
    expect(body).toMatchObject({ run_id: RUN, kind: "plan", sha256: API_RUN_WAITING.waiting_for?.[0]?.sha256, decision: "approve" });
    await expect(page.getByLabel("Approver token")).toHaveValue("");
  });

  test("a refused decision says why and records nothing", async ({ page }) => {
    await mockApi(page, { "POST /v1/approvals": (r) => json(r, API_APPROVAL_REFUSED, 403) });
    await page.goto(`/app/runs/${RUN}`);
    await page.getByLabel("Approver token").fill("not-the-token");
    await page.getByRole("button", { name: "Reject this draft" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "needs the approver's token" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "What waits for a person" })).toBeVisible();
  });

  test("a decided run shows its decisions and waits for nothing", async ({ page }) => {
    await mockApi(page, { [`GET /v1/runs/${RUN}`]: (r) => json(r, API_RUN_DECIDED) });
    await page.goto(`/app/runs/${RUN}`);
    await expect(page.getByText("Ready, approved by a person")).toBeVisible();
    await expect(page.getByRole("region", { name: /Every decision recorded/ }).getByRole("row")).toHaveCount(3);
    await expect(page.getByRole("heading", { name: "What waits for a person" })).toHaveCount(0);
  });

  test("an id that is not a run id gets its own state", async ({ page }) => {
    await mockApi(page);
    await page.goto("/app/runs/not-a-run");
    await expect(page.getByRole("heading", { name: "Not a run id", exact: true })).toBeVisible();
  });
});

test.describe("the inbox", () => {
  test("lists what waits, read only", async ({ page }) => {
    await mockApi(page);
    await page.goto("/app/inbox");
    const waiting = API_RUNS.runs.filter((r) => r.status === "waiting").length;
    await expect(page.getByRole("region", { name: /waits for a person/ }).getByRole("row")).toHaveCount(waiting + 1);
  });

  test("before the development evals there is nothing to label", async ({ page }) => {
    await mockApi(page, { "GET /v1/labels": (r) => json(r, { ...API_LABELS_OPEN, drafts: [], labelled: 0, total: 0, note: "the forty drafts come with the development evals of step 12" }) });
    await page.goto("/app/inbox");
    await expect(page.getByText("The drafts to label come with the agent evals")).toBeVisible();
  });

  test("shows each draft without what wrote it, and keeps a label only with the token", async ({ page }) => {
    let header: string | null = null;
    let body: Record<string, unknown> | null = null;
    await mockApi(page, {
      "POST /v1/labels": (r) => {
        header = r.request().headers()["authorization"] ?? null;
        body = r.request().postDataJSON() as Record<string, unknown>;
        return json(r, API_LABEL_KEPT);
      },
    });
    await page.goto("/app/inbox");
    const first = API_LABELS_OPEN.drafts[0];
    await expect(page.getByText(`0 of ${API_LABELS_OPEN.total} labelled`)).toBeVisible();
    await expect(page.getByRole("heading", { level: 3, name: /^Draft 1: a patch plan/ })).toBeVisible();
    await expect(page.getByText("floor", { exact: false })).toHaveCount(0);
    const card = page.getByRole("listitem").filter({ has: page.getByRole("heading", { name: /^Draft 1:/ }) });
    await expect(card.getByRole("button", { name: "Usable", exact: true })).toBeDisabled();
    await card.getByLabel("Why, in a sentence").fill("It names the fixed version and the steps.");
    await expect(card.getByRole("button", { name: "Usable", exact: true })).toBeDisabled();
    await page.getByLabel("Approver token").fill(TEST_TOKEN);
    await card.getByRole("button", { name: "Usable", exact: true }).click();
    await expect(card.getByText("Labelled usable")).toBeVisible();
    await expect(page.getByText(`1 of ${API_LABELS_OPEN.total} labelled`)).toBeVisible();
    expect(header).toBe(`Bearer ${TEST_TOKEN}`);
    expect(body).toMatchObject({ draft_id: first.draft_id, sha256: first.sha256, usable: true });
    await expect(card.getByLabel("A new label, and why")).toHaveValue("");
    await page.getByRole("button", { name: "Forget the token" }).click();
    await expect(page.getByLabel("Approver token")).toHaveValue("");
  });

  test("a refused label says why", async ({ page }) => {
    await mockApi(page, { "POST /v1/labels": (r) => json(r, API_LABEL_REFUSED, 403) });
    await page.goto("/app/inbox");
    const card = page.getByRole("listitem").filter({ has: page.getByRole("heading", { name: /^Draft 2:/ }) });
    await page.getByLabel("Approver token").fill("not-the-token");
    await card.getByLabel("Why, in a sentence").fill("The steps are vague.");
    await card.getByRole("button", { name: "Not usable" }).click();
    await expect(card.getByRole("alert").filter({ hasText: /token/ })).toBeVisible();
    await expect(card.getByText("Not labelled")).toBeVisible();
  });
});

test("the advisory search answers as of a day and marks every chunk untrusted", async ({ page }) => {
  let asked: URL | null = null;
  await mockApi(page, {
    "GET /v1/search": async (r, url) => {
      asked = url;
      const { API_SEARCH } = await import("../../lib/fixtures/runs");
      return json(r, API_SEARCH);
    },
  });
  await page.goto("/app/search");
  await page.getByLabel("Words").fill("logkit deserialization");
  await page.getByLabel("As of").fill("2022-01-01");
  await page.getByRole("search").getByRole("button", { name: "Search" }).click();
  await expect(page.getByText(/Untrusted text/).first()).toBeVisible();
  expect(asked).not.toBeNull();
  expect((asked as unknown as URL).searchParams.get("as_of")).toBe("2022-01-01");
  await expect(page).toHaveURL(/q=logkit/);
});
