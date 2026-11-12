import { expect, test } from "@playwright/test";
import { mockApi } from "./mock";

test("the hero's headline, sentence and primary key are on the first screen", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");
  const viewport = page.viewportSize();
  for (const loc of [page.getByRole("heading", { level: 1 }), page.locator(".hero .lead"), page.locator(".hero .key--primary")]) {
    const box = await loc.boundingBox();
    expect(box).not.toBeNull();
    expect((box?.y ?? 0) + (box?.height ?? 0)).toBeLessThanOrEqual(viewport?.height ?? 0);
  }
  await expect(page.locator(".hero h1")).toHaveText("The CVEs the NVD no longer analyzes");
});

test("the field draws the days in field.json and its legend names the source and the date", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");
  await expect(page.locator(".hero-field canvas")).toHaveCount(1);
  const legend = page.locator(".hero-field figcaption");
  await expect(legend).toContainText("One character a day");
  await expect(legend).toContainText("From gold.mart_backlog_q1 in the lake");
  await expect(legend).not.toContainText("No data release yet");
});

test("the before and after count comes from the manifest", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");
  await expect(page.locator(".ba__count")).toContainText("have no NVD CPE configuration");
  await expect(page.locator(".ba__count .mono")).toHaveText(/^\d+(\.\d)?%$/);
});

test("the system map draws later weeks as not built, and its nodes link to live pages", async ({ page }, info) => {
  await mockApi(page);
  await page.goto("/#map");
  if (info.project.name.startsWith("desktop")) {
    await expect(page.locator(".map-canvas .sysnode")).toHaveCount(11);
    await expect(page.locator(".map-canvas .sysnode[data-later='true']")).toHaveCount(4);
    await expect(page.locator(".map-canvas").getByRole("link", { name: "This console" })).toHaveAttribute("href", "/app");
  } else {
    await expect(page.locator(".map-list li")).toHaveCount(11);
    await expect(page.locator(".map-list li[data-later='true']")).toHaveCount(4);
  }
});

test("the close sends a CVE id to its ruler", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");
  await page.locator("#close-id").fill("cve-2099-0001");
  await page.locator(".closer button[type='submit']").click();
  await expect(page).toHaveURL(/\/app\/cves\/CVE-2099-0001$/);
});

test("the bar retracts on the way down and returns on the way up", async ({ page }, info) => {
  test.skip(info.project.name.startsWith("phone"), "checked once, on the desktop");
  await mockApi(page);
  await page.goto("/");
  await page.waitForLoadState("networkidle");
  await page.mouse.wheel(0, 1600);
  await expect(page.locator(".site-bar")).toHaveAttribute("data-hidden", "true");
  await page.mouse.wheel(0, -400);
  await expect(page.locator(".site-bar")).toHaveAttribute("data-hidden", "false");
});
