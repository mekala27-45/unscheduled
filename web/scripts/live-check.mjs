#!/usr/bin/env node
/**
 * The live check: the site on Vercel read in a real browser (Chromium) from this machine, against the
 * live API, with nothing mocked.
 *
 *   node web/scripts/live-check.mjs [--phase awake|asleep] [--idle-minutes 20] [--web URL] [--api URL]
 *                                   [--shots DIR] [--results DIR]
 *
 * One pass visits every route: the landing and its field, the console with one CVE the NVD did not
 * schedule and its ruler, the same CVE as known the day before its publication, the backlog, one
 * product exposure, one of the six SBOMs on the match page, the data, criteria, limits and status
 * pages, the docs architecture page and the report; for Phase 2 also one CVE of the prediction batch
 * with its predictions and the models page, and POST /v1/predict timed twice. On every route the
 * statement and the NVD notice must be on the page, no data region may show its error state, and
 * the page may log no error.
 *
 * --phase awake writes results/live/web_verify.json; both phases write their pass into
 * results/live_check.json, so the record holds the site awake and after --idle-minutes with nothing
 * sent (the API's container stopped and its database suspended). Run from the repository root.
 */
import { chromium } from "@playwright/test";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
const flag = (k, d = null) => {
  const i = args.indexOf(`--${k}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : d;
};
const ROOT = process.cwd();
const WEB = (flag("web", "https://unscheduled-triage.vercel.app") ?? "").replace(/\/$/, "");
const API = (flag("api", "https://unscheduled-api.vercel.app") ?? "").replace(/\/$/, "");
const PHASE = flag("phase", "awake");
const IDLE = Number(flag("idle-minutes", "0"));
const SHOTS = flag("shots", path.join(ROOT, "web", "test-results", "live"));
const RESULTS = flag("results", path.join(ROOT, "results"));
const SBOM = path.join(ROOT, "customer", "sboms", "rust-cli.cdx.json");
const STATEMENT_START = "unscheduled is a portfolio demonstration.";
const NVD_NOTICE = "This product uses data from the NVD API but is not endorsed or certified by the NVD.";
const now = () => new Date().toISOString().replace(/\.\d+Z$/, "Z");

async function api(pathname) {
  const res = await fetch(`${API}${pathname}`, { headers: { "user-agent": "unscheduled-live-check/0.1" } });
  if (!res.ok) throw new Error(`${pathname} answered ${res.status}`);
  return res.json();
}

/** One CVE the NVD did not schedule, published in the last 120 days, and one product, from the API. */
async function pick() {
  const since = new Date(Date.now() - 120 * 86400_000).toISOString().slice(0, 10);
  const page = await api(`/v1/cves?nvd_status=Deferred&published_from=${since}&limit=20`);
  const cve = page.items?.[0];
  if (!cve) throw new Error("the API returned no Deferred CVE from the last 120 days");
  const before = new Date(Date.parse(cve.published) - 86400_000).toISOString().slice(0, 10);
  const products = (await api("/v1/products")).products ?? [];
  // Phase 2: one CVE of the prediction batch, found by its predicted band.
  const predicted = (await api("/v1/cves?predicted_band=HIGH&limit=1")).items?.[0]?.cve_id ?? null;
  return { cve: cve.cve_id, before, product: products.map((p) => p.product_id).sort()[0], predicted };
}

/** A scored description, twice: the first answer loads the ONNX models in the container, the second
 * is warm. In the asleep phase the container has just woken for /health, so the first answer also
 * holds the models' load after a cold start. */
async function predictTwice() {
  const body = JSON.stringify({
    description: "A crafted request to the upload handler of the web console lets an unauthenticated attacker run commands as the service account.",
    cvss31_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cwes: ["CWE-78"],
  });
  const one = async () => {
    const t = Date.now();
    const res = await fetch(`${API}/v1/predict`, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "unscheduled-live-check/0.1" },
      body,
    });
    const answer = await res.json().catch(() => ({}));
    return { status: res.status, ms: Date.now() - t, band: answer.values?.find((v) => v.field === "band")?.value ?? null };
  };
  const first = await one();
  const second = await one();
  return { first, second, ok: first.status === 200 && second.status === 200 && Boolean(first.band) };
}

function routes(p) {
  return [
    { route: "/", check: async (page) => [(await page.locator(".hero-field canvas").count()) === 1 || "the hero field drew no canvas", (await page.locator(".ba__count").count()) === 1 || "the before and after count is missing"] },
    { route: "/app", check: async (page) => [(await page.getByRole("link", { name: /^CVE-\d{4}-\d+$/ }).count()) > 0 || "the console home lists no CVE"] },
    { route: "/app/cves", check: async (page) => [(await page.getByRole("link", { name: /^CVE-\d{4}-\d+$/ }).count()) > 0 || "the CVE table has no rows"] },
    {
      route: `/app/cves/${p.cve}`,
      check: async (page) => {
        await page.locator("figure.ruler").waitFor({ timeout: 20_000 });
        return [(await page.locator(".ruler__events li").count()) > 0 || "the ruler drew no event"];
      },
    },
    {
      route: `/app/cves/${p.cve}?as_of=${p.before}`,
      check: async (page) => {
        const said = page.getByText(`Nothing was known about ${p.cve}`);
        await said.first().waitFor({ timeout: 20_000 }).catch(() => {});
        return [(await said.count()) > 0 || "the day before publication did not say nothing was known"];
      },
    },
    ...(p.predicted
      ? [
          {
            route: `/app/cves/${p.predicted}`,
            check: async (page) => {
              await page.locator("section.prediction").first().waitFor({ timeout: 20_000 });
              const text = (await page.locator("main").innerText()).replace(/\s+/g, " ");
              return [
                (await page.locator("section.prediction").count()) >= 3 || "the CVE page shows fewer than three predictions",
                /Prediction of unscheduled-band version \d+/.test(text) || "the band prediction does not name its model and version",
              ];
            },
          },
        ]
      : []),
    {
      route: "/app/models",
      check: async (page) => {
        const text = (await page.locator("main").innerText()).replace(/\s+/g, " ");
        return ["unscheduled-band", "unscheduled-exploit", "unscheduled-product"].map((m) => text.includes(m) || `the models page does not list ${m}`);
      },
    },
    { route: "/app/backlog", check: async (page) => [(await page.locator("main [role='img']").count()) >= 6 || "fewer than six backlog charts"] },
    { route: "/app/products", check: async (page) => [(await page.locator("main").innerText()).includes("cloud dashboard") || "the products are not listed"] },
    {
      route: "/app/match",
      check: async (page) => {
        await page.locator("#sbom").setInputFiles(SBOM);
        const link = page.getByRole("link", { name: /^CVE-\d{4}-\d+$/ }).first();
        await link.waitFor({ timeout: 60_000 });
        return [(await page.getByRole("link", { name: /^CVE-\d{4}-\d+$/ }).count()) > 0 || "the SBOM matched nothing on the page"];
      },
    },
    { route: "/app/data", check: async () => [] },
    { route: "/app/criteria", check: async () => [] },
    { route: "/app/limits", check: async () => [] },
    { route: "/status", check: async (page) => [(await page.locator("main").innerText()).includes("Reachable") || "the status page does not show the database reachable"] },
    { route: "/docs/architecture", check: async (page) => [(await page.getByRole("heading", { level: 1 }).innerText()) === "Architecture" || "the architecture page has another title"] },
    { route: "/report/backlog", check: async (page) => [(await page.locator(".doc table").count()) > 0 || "the backlog report has no table"] },
  ];
}

async function pass(browser, picked) {
  const results = [];
  mkdirSync(SHOTS, { recursive: true });
  for (const { route, check } of routes(picked)) {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    const errors = [];
    const failed = [];
    page.on("pageerror", (e) => errors.push(String(e).slice(0, 300)));
    page.on("console", (m) => m.type() === "error" && errors.push(`${m.text().slice(0, 200)} (${m.location()?.url ?? "no url"})`));
    page.on("requestfailed", (r) => r.url().startsWith(API) && failed.push(`${r.url()} ${r.failure()?.errorText ?? ""}`));
    page.on("response", (r) => r.url().startsWith(API) && r.status() >= 500 && failed.push(`${r.url()} ${r.status()}`));
    const t0 = Date.now();
    const problems = [];
    let status = null;
    try {
      const res = await page.goto(`${WEB}${route}`, { waitUntil: "networkidle", timeout: 90_000 });
      status = res?.status() ?? null;
      for (const verdict of await check(page)) if (verdict !== true) problems.push(verdict);
      const text = (await page.locator("body").innerText()).replace(/\s+/g, " ");
      if (!text.includes(STATEMENT_START)) problems.push("the statement is not on the page");
      if (!text.includes(NVD_NOTICE)) problems.push("the NVD notice is not on the page");
      const alerts = await page.locator("main [role='alert']").allInnerTexts();
      if (alerts.some((a) => a.trim())) problems.push(`an error state shows: ${alerts.join(" | ").slice(0, 200)}`);
      const name = route === "/" ? "landing" : route.replace(/^\//, "").replace(/[/?=&]+/g, "-");
      await page.screenshot({ path: path.join(SHOTS, `${PHASE}-${name}.png`) });
    } catch (e) {
      problems.push(`${e?.name ?? "Error"}: ${String(e?.message ?? e).split("\n")[0].slice(0, 200)}`);
    }
    if (status !== 200) problems.push(`the page answered ${status}`);
    if (errors.length) problems.push(`the page logged ${errors.length} error(s): ${errors[0]}`);
    if (failed.length) problems.push(`API requests failed: ${failed.slice(0, 2).join("; ")}`);
    const ms = Date.now() - t0;
    results.push({ route, status, ms, ok: problems.length === 0, problems });
    console.log(`live: ${problems.length ? "FAIL" : "pass"} ${route} ${ms} ms${problems.length ? ": " + problems.join("; ") : ""}`);
    await context.close();
  }
  return results;
}

async function main() {
  if (IDLE > 0) {
    console.log(`live: sending nothing for ${IDLE} minutes before the ${PHASE} pass`);
    await new Promise((r) => setTimeout(r, IDLE * 60_000));
  }
  const started = now();
  const t0 = Date.now();
  const health = await fetch(`${API}/health`).then((r) => r.json().then((b) => ({ status: r.status, ms: Date.now() - t0, data_version: b.data_version })));
  const picked = await pick();
  const predict = await predictTwice();
  console.log(`live: /v1/predict ${predict.first.ms} ms then ${predict.second.ms} ms (${predict.first.status}, band ${predict.first.band})`);
  const browser = await chromium.launch(process.env.PW_CHROMIUM ? { executablePath: process.env.PW_CHROMIUM } : {});
  const results = await pass(browser, picked);
  const version = browser.version();
  await browser.close();
  const passed = results.filter((r) => r.ok).length;
  const record = {
    phase: PHASE,
    web: WEB,
    api: API,
    started_at: started,
    finished_at: now(),
    idle_minutes_before: IDLE,
    first_health: health,
    browser: `Chromium ${version}, headless, 1440 by 900`,
    client: "web/scripts/live-check.mjs, a separate machine with no credential",
    picked,
    predict,
    passed,
    total: results.length,
    result: passed === results.length && predict.ok && Boolean(picked.predicted) ? "pass" : "fail",
    routes: results,
  };
  const live = path.join(RESULTS, "live");
  mkdirSync(live, { recursive: true });
  if (PHASE === "awake") writeFileSync(path.join(live, "web_verify.json"), JSON.stringify(record, null, 1) + "\n");
  const file = path.join(RESULTS, "live_check.json");
  const all = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : {};
  all[PHASE] = record;
  writeFileSync(file, JSON.stringify(all, null, 1) + "\n");
  console.log(`live: ${PHASE} pass ${passed} of ${results.length} routes; first /health ${health.ms} ms (${health.status})`);
  process.exit(record.result === "pass" ? 0 : 1);
}

main().catch((e) => {
  console.error(`live: ${e?.message ?? e}`);
  process.exit(2);
});
