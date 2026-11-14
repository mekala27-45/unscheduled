#!/usr/bin/env node
/**
 * The design gates, run once and written down as evidence for the Phase 1 checklist.
 *
 *   node web/scripts/design-gates.mjs [--base http://127.0.0.1:3210] [--shots <dir>]
 *
 * Run from the repository root after the Playwright suite (which writes web/test-results/axe/*.json)
 * and with the built site served at --base, so sloplint's render tier can load each route. Writes:
 *   results/design/palette.json  the palette validator's output, its date, pass or fail and numbers
 *   results/design/gates.json    sloplint per route (FAIL, REFLEX, WARN counts), axe serious and
 *                                critical counts per route and viewport, and the screenshot paths
 * Exits 1 when the palette fails, sloplint reports a FAIL or a REFLEX, or axe finds anything serious.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
const flag = (k, d = null) => {
  const i = args.indexOf(`--${k}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : d;
};
const ROOT = process.cwd();
const BASE = flag("base");
const SHOTS = flag("shots", path.join(ROOT, "web", "test-results", "shots"));
const OUT = path.join(ROOT, "results", "design");
const today = new Date().toISOString().slice(0, 10);

function run(cmd, argv) {
  try {
    return { code: 0, out: execFileSync(cmd, argv, { cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] }) };
  } catch (e) {
    return { code: e.status ?? 1, out: String(e.stdout ?? "") };
  }
}

// 1. The palette, both modes, exactly the values in web/theme/palette.json.
const pal = run("node", ["scripts/validate_palette.js", "--config", "web/theme/palette.json"]);
const palette = JSON.parse(pal.out);
const paletteRecord = {
  date: today,
  command: "node scripts/validate_palette.js --config web/theme/palette.json",
  config: "web/theme/palette.json",
  result: pal.code === 0 && palette.failures === 0 ? "pass" : "fail",
  failures: palette.failures,
  modes: palette.modes,
};

// 2. sloplint: the landing at genre modern-minimal, the docs and the report as pages of the same
// site, the console and /design at scope app.
const LANDING = { genre: "modern-minimal", files: ["web/styles/landing.css", "web/styles/tokens.css", "web/styles/base.css", "web/app/(site)/page.tsx", "web/components/site"], routes: ["/"] };
const DOCS = {
  genre: "modern-minimal",
  files: ["web/styles/docs.css", "web/styles/landing.css", "web/styles/tokens.css", "web/styles/base.css", "web/app/(site)/docs", "web/app/(site)/report", "web/components/site/doc-view.tsx"],
  routes: ["/docs", "/docs/architecture", "/docs/spec", "/docs/models", "/report", "/report/backlog", "/report/models"],
};
const CONSOLE = {
  scope: "app",
  files: ["web/styles/console.css", "web/styles/tokens.css", "web/styles/base.css", "web/components/console", "web/components/ui", "web/components/ruler", "web/components/charts", "web/app/(console)", "web/app/(site)/design"],
  routes: ["/app", "/app/cves", "/app/cves/CVE-2099-0001", "/app/backlog", "/app/products", "/app/match", "/app/data", "/app/models", "/app/criteria", "/app/limits", "/status", "/design"],
};

function sloplint(set) {
  const argv = ["tools/hallmark/sloplint.mjs", ...set.files, "--json"];
  if (set.genre) argv.push("--genre", set.genre);
  if (set.scope) argv.push("--scope", set.scope);
  if (BASE) for (const r of set.routes) argv.push("--url", `${BASE}${r}`);
  const res = run("node", argv);
  const report = JSON.parse(res.out);
  const isUrl = (f) => /^https?:\/\//.test(String(f.file ?? ""));
  const count = (list, grade) => list.filter((f) => f.grade === grade).length;
  const statics = report.findings.filter((f) => !isUrl(f));
  return set.routes.map((route) => {
    const own = report.findings.filter((f) => isUrl(f) && new URL(f.file).pathname === route);
    const all = [...statics, ...own];
    return {
      route,
      genre: set.genre ?? null,
      scope: set.scope ?? "page",
      render: BASE ? report.summary.render !== "off" : false,
      fail: count(all, "FAIL"),
      reflex: count(all, "REFLEX"),
      warn: count(all, "WARN"),
      dismissed: count(all, "DISMISSED"),
      answered: count(all, "ANSWERED"),
      result: count(all, "FAIL") + count(all, "REFLEX") === 0 ? "pass" : "fail",
      findings: all.filter((f) => f.grade !== "NOTE").map((f) => `${f.grade} ${f.gate} ${f.evidence}`),
    };
  });
}

const slop = [...sloplint(LANDING), ...sloplint(DOCS), ...sloplint(CONSOLE)];

// 3. axe, from the Playwright suite: serious and critical per route and per viewport and theme.
const axeDir = path.join(ROOT, "web", "test-results", "axe");
const axe = {};
if (existsSync(axeDir)) {
  for (const name of readdirSync(axeDir).filter((n) => n.endsWith(".json")).sort()) {
    const r = JSON.parse(readFileSync(path.join(axeDir, name), "utf8"));
    axe[r.route] ??= { route: r.route, serious: 0, critical: 0, projects: {} };
    axe[r.route].serious += r.serious;
    axe[r.route].critical += r.critical;
    axe[r.route].projects[r.project] = { serious: r.serious, critical: r.critical, other: r.other };
  }
}
const axeRows = Object.values(axe);

// 4. The screenshots of the look review.
const shots = existsSync(SHOTS)
  ? readdirSync(SHOTS)
      .filter((n) => /^(landing|console-home|cve-fixture|design)-\d+x\d+-(light|dark)\.png$/.test(n))
      .sort()
      .map((n) => path.join(SHOTS, n))
  : [];

// 5. Lighthouse, when lhci has written its reports to web/lighthouse: the median score per URL
// against the targets of section 15 (the landing: performance 0.9, accessibility 1, layout shift
// under 0.1; the ruler: accessibility 0.95).
const lhDir = path.join(ROOT, "web", "lighthouse");
const lhRuns = {};
if (existsSync(lhDir)) {
  for (const name of readdirSync(lhDir).filter((n) => n.endsWith(".json") && !n.startsWith("manifest"))) {
    const report = JSON.parse(readFileSync(path.join(lhDir, name), "utf8"));
    if (!report.categories) continue;
    const url = new URL(report.finalUrl ?? report.requestedUrl).pathname;
    (lhRuns[url] ??= []).push({
      performance: report.categories.performance?.score ?? null,
      accessibility: report.categories.accessibility?.score ?? null,
      cls: report.audits?.["cumulative-layout-shift"]?.numericValue ?? null,
    });
  }
}
const median = (xs) => {
  const v = xs.filter((x) => x !== null).sort((a, b) => a - b);
  return v.length ? v[Math.floor((v.length - 1) / 2)] : null;
};
const lhRows = Object.entries(lhRuns).map(([url, runs]) => {
  const row = {
    url,
    runs: runs.length,
    performance: median(runs.map((r) => r.performance)),
    accessibility: median(runs.map((r) => r.accessibility)),
    cls: median(runs.map((r) => r.cls)),
  };
  row.result =
    url === "/"
      ? row.performance >= 0.9 && row.accessibility === 1 && row.cls < 0.1
        ? "pass"
        : "fail"
      : row.accessibility >= 0.95
        ? "pass"
        : "fail";
  return row;
});

const gates = {
  date: today,
  base: BASE,
  sloplint: { result: slop.every((r) => r.result === "pass") ? "pass" : "fail", routes: slop },
  axe: {
    result: axeRows.length > 0 && axeRows.every((r) => r.serious + r.critical === 0) ? "pass" : axeRows.length ? "fail" : "not run",
    source: "web/test-results/axe, written by tests/e2e/routes.spec.ts at 390 and 1440 px in both themes",
    routes: axeRows,
  },
  lighthouse: {
    result: lhRows.length === 0 ? "not run" : lhRows.every((r) => r.result === "pass") ? "pass" : "fail",
    source: "web/lighthouse, written by lhci autorun with web/lighthouserc.json (desktop preset)",
    urls: lhRows,
  },
  screenshots: shots,
};

mkdirSync(OUT, { recursive: true });
writeFileSync(path.join(OUT, "palette.json"), JSON.stringify(paletteRecord, null, 1) + "\n");
writeFileSync(path.join(OUT, "gates.json"), JSON.stringify(gates, null, 1) + "\n");
console.log(
  `palette ${paletteRecord.result}; sloplint ${gates.sloplint.result} over ${slop.length} routes; ` +
    `axe ${gates.axe.result} over ${axeRows.length} routes; lighthouse ${gates.lighthouse.result} over ` +
    `${lhRows.length} urls; ${shots.length} screenshots`,
);
const ok = [paletteRecord.result, gates.sloplint.result, gates.axe.result].every((r) => r === "pass");
process.exit(ok && gates.lighthouse.result !== "fail" ? 0 : 1);
