import type { Page, Route } from "@playwright/test";
import { CVE_FIXTURE, FIXTURE_ID, SUMMARY_FIXTURE, TIMELINE_FIXTURE } from "../../lib/fixtures/cve";
import { STATEMENT } from "../../lib/statement";

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

/** What the API stub of step one answers today: health and meta in its older shape, 404 for the rest. */
export const STUB_HEALTH = { status: "ok", version: "0.1.0.dev0", database: "not yet connected", statement: STATEMENT };
export const STUB_META = { version: "0.1.0.dev0", statement: STATEMENT, nvd_notice: "", attribution: [], locks: {} };

export type Handler = (route: Route, url: URL) => Promise<void> | void;

/**
 * Answers every request to the test API. Overrides are matched on "METHOD /path" first; then the
 * fixture CVE (FIXTURE, not data), then the stub's own answers, then 404 as FastAPI writes it.
 */
export async function mockApi(page: Page, overrides: Record<string, Handler> = {}) {
  await page.route(`${API}/**`, async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    if (req.method() === "OPTIONS") return route.fulfill({ status: 204, headers: CORS });
    const key = `${req.method()} ${url.pathname}`;
    if (overrides[key]) return overrides[key](route, url);
    if (url.pathname === `/v1/cves/${FIXTURE_ID}`) return json(route, CVE_FIXTURE);
    if (url.pathname === `/v1/cves/${FIXTURE_ID}/timeline`) return json(route, TIMELINE_FIXTURE);
    if (url.pathname === "/health") return json(route, STUB_HEALTH);
    if (url.pathname === "/v1/meta") return json(route, STUB_META);
    return json(route, { detail: "Not Found" }, 404);
  });
}

export const cveList = (items = SUMMARY_FIXTURE, next: string | null = null) => ({ data_version: "fixture", statement: STATEMENT, items, next_cursor: next });
