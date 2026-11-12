import { expect, test } from "@playwright/test";
import { mockApi } from "./mock";

test("the docs list every document by section and open each one", async ({ page }) => {
  await mockApi(page);
  await page.goto("/docs");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Docs");
  for (const section of ["How it is built", "Decisions", "Runbooks", "The data and the customer"]) {
    await expect(page.getByRole("heading", { level: 2, name: section })).toBeVisible();
  }
  await expect(page.locator(".doc-group").filter({ hasText: "Decisions" }).locator(".doc-list li")).toHaveCount(7);
  await page.getByRole("link", { name: "Architecture", exact: true }).click();
  await expect(page).toHaveURL(/\/docs\/architecture$/);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Architecture");
  await expect(page.locator(".doc-page__source a")).toHaveAttribute("href", /\/blob\/main\/ARCHITECTURE\.md$/);
});

test("a long document has contents that jump to its sections", async ({ page }, info) => {
  await mockApi(page);
  await page.goto("/docs/spec");
  const contents = page.getByRole("navigation", { name: "Contents" });
  await expect(contents).toBeVisible();
  const first = contents.getByRole("link").first();
  const target = (await first.getAttribute("href")) ?? "";
  expect(target).toMatch(/^#/);
  await first.click();
  await expect(page.locator(`[id="${target.slice(1)}"]`)).toBeInViewport();
  if (info.project.name.startsWith("phone")) {
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  }
});

test("the report lists its documents and renders the backlog with its tables", async ({ page }) => {
  await mockApi(page);
  await page.goto("/report");
  await expect(page.locator(".doc-list li")).toHaveCount(5);
  await page.locator(".doc-list a").first().click();
  await expect(page).toHaveURL(/\/report\/backlog$/);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("The backlog, in words and numbers");
  await expect(page.locator(".doc table").first()).toBeVisible();
  await expect(page.getByRole("heading", { level: 2, name: /^Q1, the analysis delay/ })).toBeVisible();
});
