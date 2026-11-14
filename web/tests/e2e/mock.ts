import type { Page, Route } from "@playwright/test";
import { API_CVE, API_HEALTH_EMPTY, API_META_EMPTY, API_MODELS, API_SUMMARIES, API_TIMELINE, FIXTURE_ID, apiPage } from "../../lib/fixtures/api";

export const API = "http://api.unscheduled.test";

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "content-type",
  "access-control-allow-methods": "GET, POST, OPTIONS",
};

export const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, headers: { ...CORS, "content-type": status >= 400 && isProblem(body) ? "application/problem+json" : "application/json" }, body: JSON.stringify(body) });

function isProblem(body: unknown): boolean {
  return typeof body === "object" && body !== null && "title" in body && "status" in body;
}

/** The API before a bundle is loaded, in its own shape: health and meta answer, the data routes 503. */
export const STUB_HEALTH = API_HEALTH_EMPTY;
export const STUB_META = API_META_EMPTY;

export type Handler = (route: Route, url: URL) => Promise<void> | void;

/**
 * Answers every request to the test API in the shape of openapi.json. Overrides are matched on
 * "METHOD /path" first; then the fixture CVE (FIXTURE, not data), then health and meta, then 404 as
 * FastAPI writes it.
 */
export async function mockApi(page: Page, overrides: Record<string, Handler> = {}) {
  await page.route(`${API}/**`, async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    if (req.method() === "OPTIONS") return route.fulfill({ status: 204, headers: CORS });
    const key = `${req.method()} ${url.pathname}`;
    if (overrides[key]) return overrides[key](route, url);
    if (url.pathname === `/v1/cves/${FIXTURE_ID}`) return json(route, API_CVE);
    if (url.pathname === `/v1/cves/${FIXTURE_ID}/timeline`) return json(route, API_TIMELINE);
    if (url.pathname === "/health") return json(route, STUB_HEALTH);
    if (url.pathname === "/v1/meta") return json(route, STUB_META);
    if (url.pathname === "/v1/models") return json(route, API_MODELS);
    return json(route, { detail: "Not Found" }, 404);
  });
}

export const cveList = (items = API_SUMMARIES, next: string | null = null) => apiPage(items, next);
