import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import path from "node:path";
import { mockApi } from "./mock";

test("the docs list every document by section and open each one", async ({ page }) => {
  await mockApi(page);
  await page.goto("/docs");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Docs");
  for (const section of ["Start here", "How it is built", "Decisions", "Runbooks", "The data and the customer"]) {
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

for (const [slug, name, what] of [
  ["as-of", "status", "the NVD status lifecycle"],
  ["adr-0002", "slice", "the tables of the slice"],
  ["adr-0004", "match", "a match as a sequence"],
  ["adr-0007", "sync", "the sync as a sequence"],
] as const) {
  test(`/docs/${slug} opens with ${what}`, async ({ page }) => {
    await mockApi(page);
    await page.goto(`/docs/${slug}`);
    const figure = page.locator(".doc-figure");
    await expect(figure).toBeVisible();
    await expect(figure.locator("img").first()).toHaveAttribute("src", new RegExp(`/diagrams/${name}-(light|dark)\\.svg$`));
    await expect(figure.getByRole("link", { name: "Open the diagram you can explore" })).toHaveAttribute("href", `/diagrams/${name}.html`);
  });
}

test("the API reference lists every route, read from openapi.json", async ({ page }) => {
  const spec = JSON.parse(readFileSync(path.join(__dirname, "..", "..", "..", "openapi.json"), "utf8")) as {
    paths: Record<string, Record<string, unknown>>;
  };
  const routes = Object.entries(spec.paths).flatMap(([route, ops]) =>
    Object.keys(ops)
      .filter((m) => ["get", "post", "put", "patch", "delete"].includes(m))
      .map((m) => `${m.toUpperCase()} ${route}`),
  );
  expect(routes.length).toBeGreaterThan(0);
  await mockApi(page);
  await page.goto("/docs/api");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("API reference");
  const headings = page.locator(".doc h2");
  await expect(headings).toHaveCount(routes.length);
  expect((await headings.allInnerTexts()).map((t) => t.trim()).sort()).toEqual([...routes].sort());
  await expect(page.getByRole("heading", { level: 2, name: "GET /v1/cves/{cve_id}", exact: true })).toBeVisible();
});
