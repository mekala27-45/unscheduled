import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { STATEMENT, NVD_NOTICE, GHSA_ATTRIBUTION } from "../../lib/statement";
import { FIXTURE_ID } from "../../lib/fixtures/cve";
import { mockApi } from "./mock";

export const ROUTES = [
  "/",
  "/design",
  "/app",
  "/app/cves",
  `/app/cves/${FIXTURE_ID}`,
  "/app/backlog",
  "/app/products",
  "/app/match",
  "/app/data",
  "/app/models",
  "/app/criteria",
  "/app/limits",
  "/status",
  "/docs",
  "/docs/quickstart",
  "/docs/api",
  "/docs/architecture",
  "/docs/as-of",
  "/docs/methods",
  "/docs/models",
  "/docs/spec",
  "/docs/changelog",
  "/docs/adr-0002",
  "/docs/adr-0004",
  "/docs/adr-0007",
  "/docs/adr-0009",
  "/docs/adr-0010",
  "/report",
  "/report/backlog",
  "/report/discovery",
  "/report/models",
  "/report/model-band",
  "/no-such-page",
];

const flat = (s: string) => s.replace(/\s+/g, " ").trim();

for (const route of ROUTES) {
  test(`${route}: the statement and notices, no sideways scroll, no serious or critical axe finding`, async ({ page }, info) => {
    await mockApi(page);
    await page.goto(route);
    await page.waitForLoadState("networkidle");
    await expect(page.locator("footer").last()).toBeVisible();

    const text = flat((await page.locator("body").innerText()) ?? "");
    expect(text).toContain(flat(STATEMENT.replace(NVD_NOTICE, "")));
    expect(text).toContain(NVD_NOTICE);
    expect(text).toContain(GHSA_ATTRIBUTION.slice(0, 50));
    expect(text).not.toMatch(/[\u2013\u2014]/);

    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(0);

    const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"]).analyze();
    const blocking = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
    const out = path.join("test-results", "axe");
    mkdirSync(out, { recursive: true });
    writeFileSync(
      path.join(out, `${info.project.name}${route === "/" ? "-home" : route.replace(/\//g, "-")}.json`),
      JSON.stringify({
        route,
        project: info.project.name,
        serious: blocking.filter((v) => v.impact === "serious").length,
        critical: blocking.filter((v) => v.impact === "critical").length,
        other: results.violations.filter((v) => v.impact !== "serious" && v.impact !== "critical").map((v) => `${v.id} (${v.impact})`),
      }),
    );
    expect(blocking.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
  });
}
