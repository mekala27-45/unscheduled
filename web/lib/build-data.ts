/**
 * Files the data build writes, read once when the site is built. Each reader returns null (or an
 * empty record) when its file is absent, and the page shows what is missing instead of a value.
 * Server code only: these run in server components at build time.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { parseFieldData, type FieldData } from "./field";

// Build time only: every reader runs while static pages render, so nothing here is traced into a function.
const WEB_ROOT = existsSync(path.join(/*turbopackIgnore: true*/ process.cwd(), "next.config.ts")) ? process.cwd() : path.join(/*turbopackIgnore: true*/ process.cwd(), "web");
const REPO_ROOT = path.resolve(/*turbopackIgnore: true*/ WEB_ROOT, "..");

function readJson(file: string): unknown | undefined {
  if (!existsSync(file)) return undefined;
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

export type Loaded<T> = { state: "absent" } | { state: "unreadable"; file: string } | { state: "ok"; value: T };

/** web/public/data/field.json, the daily counts behind the hero's character field. */
export function readField(): Loaded<FieldData> {
  const file = path.join(/*turbopackIgnore: true*/ WEB_ROOT, "public", "data", "field.json");
  const raw = readJson(file);
  if (raw === undefined) return { state: "absent" };
  const value = parseFieldData(raw);
  return value ? { state: "ok", value } : { state: "unreadable", file: "web/public/data/field.json" };
}

export type ManifestLite = { as_of: string; values: Record<string, { value: number | string | null; fmt: string }> };

/** results/manifest.json, the only place a published number comes from. */
export function readManifest(): Loaded<ManifestLite> {
  const raw = readJson(path.join(/*turbopackIgnore: true*/ REPO_ROOT, "results", "manifest.json"));
  if (raw === undefined) return { state: "absent" };
  if (typeof raw !== "object" || raw === null || typeof (raw as ManifestLite).as_of !== "string") {
    return { state: "unreadable", file: "results/manifest.json" };
  }
  const m = raw as ManifestLite;
  return { state: "ok", value: { as_of: m.as_of, values: m.values ?? {} } };
}

export type LockLite = { fetched_at: string; digest: string; files: number };

/**
 * data/locks/<source>.lock.json as the fetchers write it:
 *   { source, lock_version, updated_at, entries: [{ name, url, sha256, size, rows, fetched_at }] }
 * The last fetch is updated_at; the digest shown is the newest entry's.
 */
export function readLocks(): Record<string, Loaded<LockLite>> {
  const dir = path.join(/*turbopackIgnore: true*/ REPO_ROOT, "data", "locks");
  const out: Record<string, Loaded<LockLite>> = {};
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    if (!name.endsWith(".lock.json")) continue;
    const source = name.replace(/\.lock\.json$/, "");
    const raw = readJson(path.join(/*turbopackIgnore: true*/ dir, name)) as Record<string, unknown> | null | undefined;
    const entries = Array.isArray(raw?.entries) ? (raw.entries as Record<string, unknown>[]) : [];
    const newest = [...entries].filter((e) => typeof e.fetched_at === "string" && typeof e.sha256 === "string").sort((a, b) => String(b.fetched_at).localeCompare(String(a.fetched_at)))[0];
    const updated = typeof raw?.updated_at === "string" ? raw.updated_at : (newest?.fetched_at as string | undefined);
    out[source] =
      newest && updated
        ? { state: "ok", value: { fetched_at: updated, digest: String(newest.sha256), files: entries.length } }
        : { state: "unreadable", file: `data/locks/${name}` };
  }
  return out;
}

export type Criterion = { id: string; sentence: string; threshold: string; phase: string; evidence: string | null };
export type Criteria = { criteria: Criterion[]; hash: string | null; registeredAt: string | null };

/** config/criteria.yaml and evaluation/registration.json, hashed before any test CVE is scored. */
export function readCriteria(): Loaded<Criteria> {
  const file = path.join(/*turbopackIgnore: true*/ REPO_ROOT, "config", "criteria.yaml");
  if (!existsSync(file)) return { state: "absent" };
  try {
    const doc = parseYaml(readFileSync(file, "utf8")) as unknown;
    const list = Array.isArray(doc) ? doc : (doc as { criteria?: unknown })?.criteria;
    if (!Array.isArray(list)) return { state: "unreadable", file: "config/criteria.yaml" };
    const criteria: Criterion[] = [];
    for (const item of list) {
      const c = item as Record<string, unknown>;
      if (typeof c.id !== "string" || typeof c.sentence !== "string") return { state: "unreadable", file: "config/criteria.yaml" };
      criteria.push({
        id: c.id,
        sentence: c.sentence,
        threshold: String(c.threshold ?? ""),
        phase: String(c.phase ?? ""),
        evidence: typeof c.evidence === "string" ? c.evidence : null,
      });
    }
    const reg = readJson(path.join(/*turbopackIgnore: true*/ REPO_ROOT, "evaluation", "registration.json")) as Record<string, unknown> | null | undefined;
    const hash = typeof reg?.hash === "string" ? reg.hash : typeof reg?.sha256 === "string" ? reg.sha256 : null;
    const registeredAt = typeof reg?.registered_at === "string" ? reg.registered_at : null;
    return { state: "ok", value: { criteria, hash, registeredAt } };
  } catch {
    return { state: "unreadable", file: "config/criteria.yaml" };
  }
}

export type ScreenName = "ruler" | "backlog" | "exposure" | "match";
export type Screen = { light: string | null; dark: string | null; width: number; height: number };

/** Console captures in web/public/screens/<name>-light.png and -dark.png, made by tools/hallmark/capture.mjs. */
export function readScreens(): Record<ScreenName, Screen> {
  const names: ScreenName[] = ["ruler", "backlog", "exposure", "match"];
  const out = {} as Record<ScreenName, Screen>;
  for (const name of names) {
    const find = (mode: string) => (existsSync(path.join(/*turbopackIgnore: true*/ WEB_ROOT, "public", "screens", `${name}-${mode}.png`)) ? `/screens/${name}-${mode}.png` : null);
    out[name] = { light: find("light"), dark: find("dark"), width: 2880, height: 1800 };
  }
  return out;
}

export function webVersion(): string {
  const pkg = readJson(path.join(/*turbopackIgnore: true*/ WEB_ROOT, "package.json")) as { version?: string } | null | undefined;
  return pkg?.version ?? "unknown";
}
