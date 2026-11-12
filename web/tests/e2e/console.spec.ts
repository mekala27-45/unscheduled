import { expect, test } from "@playwright/test";
import { API_CVE, API_SUMMARIES } from "../../lib/fixtures/api";
import { FIXTURE_ID, FIXTURE_NOW, SUMMARY_FIXTURE } from "../../lib/fixtures/cve";
import { cveList, json, mockApi } from "./mock";

test.describe("the four states of the CVE table", () => {
  test("loading shows a skeleton in the shape of the table", async ({ page }) => {
    await mockApi(page, { "GET /v1/cves": () => new Promise(() => {}) });
    await page.goto("/app/cves");
    await expect(page.locator("[aria-busy='true']").first()).toBeVisible();
    await expect(page.getByRole("status").filter({ hasText: "Loading CVEs" })).toBeAttached();
  });

  test("empty says what belongs here and offers the one action", async ({ page }) => {
    await mockApi(page, { "GET /v1/cves": (r) => json(r, cveList([])) });
    await page.goto("/app/cves");
    await expect(page.getByText("The API holds no CVEs yet")).toBeVisible();
    await expect(page.getByRole("link", { name: "Open the data page" })).toBeVisible();
  });

  test("error says what broke and what to do, from the problem document", async ({ page }) => {
    await mockApi(page, { "GET /v1/cves": (r) => json(r, { type: "about:blank", title: "The database is not reachable", status: 503, detail: "Neon did not answer within 5 seconds." }, 503) });
    await page.goto("/app/cves");
    const alert = page.locator("main").getByRole("alert");
    await expect(alert).toContainText("The database is not reachable");
    await expect(alert).toContainText("Neon did not answer");
    await expect(page.getByRole("button", { name: "Try again" })).toBeVisible();
  });

  test("full draws the rows; j and k move, Enter opens", async ({ page }) => {
    await mockApi(page, { "GET /v1/cves": (r) => json(r, cveList(API_SUMMARIES)) });
    await page.goto("/app/cves");
    await expect(page.getByRole("link", { name: SUMMARY_FIXTURE[0].id })).toBeVisible();
    await page.locator("main h1").click();
    await page.keyboard.press("j");
    await page.keyboard.press("j");
    await page.keyboard.press("k");
    await expect(page.locator("tr[data-active='true']")).toContainText(SUMMARY_FIXTURE[0].id);
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(new RegExp(`/app/cves/${SUMMARY_FIXTURE[0].id}$`));
  });

  test("filters live in the address bar", async ({ page }) => {
    let seen = "";
    await mockApi(page, {
      "GET /v1/cves": (r, url) => {
        seen = url.search;
        return json(r, cveList([]));
      },
    });
    await page.goto("/app/cves");
    await page.getByLabel("KEV").selectOption("listed");
    await expect(page).toHaveURL(/kev=listed/);
    await page.getByLabel("CWE").fill("cwe-79");
    await page.getByRole("button", { name: "Apply" }).click();
    await expect(page).toHaveURL(/cwe=CWE-79/);
    await expect.poll(() => seen).toContain("cwe=CWE-79");
    await expect(page.getByText("No CVE matches these filters")).toBeVisible();
  });
});

test.describe("the keyboard", () => {
  test("Ctrl K opens the palette, a CVE id opens its page", async ({ page }) => {
    await mockApi(page);
    await page.goto("/app/limits");
    await page.keyboard.press("Control+k");
    const input = page.getByRole("dialog").getByRole("combobox");
    await expect(input).toBeFocused();
    await input.fill(FIXTURE_ID.toLowerCase());
    await expect(page.getByRole("option", { name: `Open ${FIXTURE_ID}` })).toBeVisible();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(new RegExp(`/app/cves/${FIXTURE_ID}$`));
  });

  test("g then a letter jumps; slash focuses search; question mark shows the keys; escape closes", async ({ page }, info) => {
    test.skip(info.project.name.startsWith("phone"), "keyboard shortcuts are for a keyboard");
    await mockApi(page);
    await page.goto("/app/limits");
    await page.locator("main h1").click();
    await page.keyboard.press("g");
    await page.keyboard.press("b");
    await expect(page).toHaveURL(/\/app\/backlog$/);
    await page.goto("/app");
    await page.locator("main h1").click();
    await page.keyboard.press("/");
    await expect(page.locator("#lookup")).toBeFocused();
    await page.locator("main h1").click();
    await page.keyboard.press("?");
    await expect(page.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);
  });

  test("the sidebar becomes a menu under 60rem", async ({ page }, info) => {
    await mockApi(page);
    await page.goto("/app");
    const menu = page.getByRole("button", { name: "Open the console menu" });
    if (info.project.name.startsWith("phone")) {
      await expect(menu).toBeVisible();
      await menu.click();
      await page.getByRole("dialog").getByRole("link", { name: "Backlog" }).click();
      await expect(page).toHaveURL(/\/app\/backlog$/);
    } else {
      await expect(menu).toBeHidden();
      await expect(page.getByRole("navigation", { name: "Console" }).first()).toBeVisible();
    }
  });
});

test.describe("the ruler", () => {
  test("draws every fixture event and the open NVD wait", async ({ page }) => {
    await page.clock.setFixedTime(new Date(FIXTURE_NOW));
    await mockApi(page);
    await page.goto(`/app/cves/${FIXTURE_ID}`);
    const ruler = page.locator("figure.ruler");
    await expect(ruler).toBeVisible();
    await expect(ruler.locator(".ruler__events li")).toHaveCount(7);
    await expect(ruler.getByRole("img")).toHaveAttribute("aria-label", /NVD, Awaiting Analysis, 249 days and counting/);
    await expect(page.getByText("Data version fixture")).toBeVisible();
  });

  test("the as-of date redraws the record as known that day, and lives in the address", async ({ page }) => {
    let asked = "";
    await mockApi(page, {
      [`GET /v1/cves/${FIXTURE_ID}`]: async (r, url) => {
        asked = url.searchParams.get("as_of") ?? "";
        return json(r, { ...API_CVE, as_of: asked || null });
      },
    });
    await page.goto(`/app/cves/${FIXTURE_ID}`);
    await page.getByLabel("As known on").fill("2026-03-10");
    await page.getByRole("button", { name: "Redraw" }).click();
    await expect(page).toHaveURL(/as_of=2026-03-10/);
    await expect(page.locator(".ruler__events li")).toHaveCount(3);
    await expect.poll(() => asked).toBe("2026-03-10");
    await page.getByLabel("As known on").fill("2026-01-01");
    await page.getByRole("button", { name: "Redraw" }).click();
    await expect(page.getByText(`Nothing was known about ${FIXTURE_ID}`)).toBeVisible();
  });

  test("a string that is not a CVE id gets its own state", async ({ page }) => {
    await mockApi(page);
    await page.goto("/app/cves/not-a-cve");
    await expect(page.getByRole("heading", { name: "Not a CVE id", exact: true })).toBeVisible();
  });
});

test.describe("the match", () => {
  const sbom = { bomFormat: "CycloneDX", specVersion: "1.6", components: [{ name: "example-server", version: "2.4.0", purl: "pkg:npm/example-server@2.4.0" }] };

  test("sends a CycloneDX file and shows the findings and the digest", async ({ page }) => {
    let body: unknown = null;
    await mockApi(page, {
      "POST /v1/match": (r) => {
        body = r.request().postDataJSON();
        return json(r, {
          data_version: "fixture",
          statement: "fixture",
          as_of: "2026-11-07T12:00:00Z",
          stored: "the digest and the counts",
          engine: "unscheduled-match over fixture records",
          duration_ms: 12.5,
          sbom: { sha256: "sha256:fixture", format: "cyclonedx", spec_version: "1.6", bytes: 180, components: 1, with_purl: 1, without_purl: 0 },
          counts: { findings: 1, components_matched: 1, advisories_read: 1, distinct_cves: 1 },
          findings: [
            {
              product: "upload",
              component: "example-server",
              package: "example-server",
              version: "2.4.0",
              purl: "pkg:npm/example-server@2.4.0",
              ecosystem: "npm",
              primary_id: "GHSA-xxxx-xxxx-xxxx",
              advisory_ids: ["GHSA-xxxx-xxxx-xxxx"],
              cve_aliases: [FIXTURE_ID],
              upstream_cves: [],
              matches: [{ advisory_id: "GHSA-xxxx-xxxx-xxxx", source: "ghsa", sources: ["ghsa"], via: "range", matched_range: ">=2.0.0, <2.4.1", fixed: ["2.4.1"] }],
              fixed_versions: ["2.4.1"],
              fix_available: true,
              known_from: "2026-03-05T09:12:00Z",
              known_from_rule: "published",
              as_of: "2026-11-07T12:00:00Z",
            },
          ],
        });
      },
    });
    await page.goto("/app/match");
    await expect(page.getByText("No SBOM matched yet")).toBeVisible();
    await page.locator("#sbom").setInputFiles({ name: "fixture.cdx.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(sbom)) });
    await expect(page.getByRole("link", { name: FIXTURE_ID })).toBeVisible();
    expect(body).toMatchObject({ bomFormat: "CycloneDX" });
    await expect(page.getByText("sha256:fixture")).toBeVisible();
  });

  test("refuses a file over 2 MB before sending it", async ({ page }) => {
    let sent = false;
    await mockApi(page, { "POST /v1/match": (r) => ((sent = true), json(r, {})) });
    await page.goto("/app/match");
    await page.locator("#sbom").setInputFiles({ name: "big.json", mimeType: "application/json", buffer: Buffer.alloc(2 * 1024 * 1024 + 10, 32) });
    await expect(page.getByText(/the API takes SBOMs up to 2 MB/)).toBeVisible();
    expect(sent).toBe(false);
  });
});

test("the theme toggle wins over the system and survives a reload", async ({ page }, info) => {
  await mockApi(page);
  await page.goto("/app/limits");
  const want = info.project.name.endsWith("dark") ? "light" : "dark";
  await page.getByRole("button", { name: /Colour theme/ }).click();
  await page.getByRole("menuitemradio", { name: want === "dark" ? "Dark" : "Light" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", want);
  const paper = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", want);
  expect(await page.evaluate(() => getComputedStyle(document.body).backgroundColor)).toBe(paper);
});
