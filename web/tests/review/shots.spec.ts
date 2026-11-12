import { test } from "@playwright/test";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { FIXTURE_ID } from "../../lib/fixtures/cve";
import { mockApi } from "../e2e/mock";

/**
 * Screenshots for the look review. The console answers as the API stub answers today, so its regions
 * show their real empty and error states; the CVE page reads the labelled fixture (data version
 * "fixture") so the ruler has events to draw. SHOTS_DIR says where the files go.
 */
const OUT = process.env.SHOTS_DIR ?? path.join("test-results", "shots");
const PAGES = [
  { name: "landing", route: "/" },
  { name: "console-home", route: "/app" },
  { name: "cve-fixture", route: `/app/cves/${FIXTURE_ID}` },
  { name: "design", route: "/design" },
];

for (const p of PAGES) {
  test(`shoot ${p.name}`, async ({ page }, info) => {
    mkdirSync(OUT, { recursive: true });
    await mockApi(page);
    await page.goto(p.route);
    await page.waitForLoadState("networkidle");
    await page.evaluate(() => document.fonts.ready);
    await page.waitForTimeout(400);
    const size = info.project.name.startsWith("desktop") ? "1440x900" : "390x844";
    const theme = info.project.name.endsWith("dark") ? "dark" : "light";
    await page.screenshot({ path: path.join(OUT, `${p.name}-${size}-${theme}.png`) });
    if (process.env.SHOTS_FULL) await page.screenshot({ path: path.join(OUT, "full", `${p.name}-${size}-${theme}.png`), fullPage: true });
  });
}
