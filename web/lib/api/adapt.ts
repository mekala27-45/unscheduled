/**
 * From the API's answers (lib/api/openapi.ts) to the shapes the pages read (lib/api/view.ts).
 * Each function only renames, picks and orders what the API sent; nothing is invented. Where the
 * API sends a field as free JSON (the backlog, a product's attributes, a finding's body), the value
 * is read with a type check and an absent or odd value becomes null, never a guess.
 */
import type { components } from "./openapi";
import type {
  Backlog,
  BacklogQuestion,
  Cve,
  CveField,
  CveList,
  CveSummary,
  EpssOffset,
  Exposure,
  Finding,
  Health,
  Lock,
  MatchResult,
  Meta,
  Product,
  ProductList,
  QuarantineCount,
  RunLedgerRow,
  SourceFreshness,
  Timeline,
  TimelineEvent,
} from "./view";

type S = components["schemas"];

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): string | null => (typeof v === "string" && v.length > 0 ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const bool = (v: unknown): boolean | null => (typeof v === "boolean" ? v : null);
const texts = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

const HOUR = 3_600_000;
/** How old a lock may be before its source counts as stale. */
const GRACE: Record<string, number> = { hourly: 2 * HOUR, daily: 36 * HOUR };

/** The served fields in the order the record page lists them, with the words it uses. */
export const FIELD_LABELS: [string, string][] = [
  ["state", "State in the CVE List"],
  ["published", "Published"],
  ["last_modified", "Last change seen"],
  ["filer", "Filer"],
  ["filer_type", "Filer type"],
  ["nvd_status", "NVD status"],
  ["nvd_status_since", "NVD status since"],
  ["cwes", "CWE"],
  ["filer_cvss31_vector", "Filer CVSS 3.1 vector"],
  ["filer_cvss31_score", "Filer CVSS 3.1 score"],
  ["filer_cvss31_band", "Filer CVSS 3.1 band"],
  ["filer_cvss40_vector", "Filer CVSS 4.0 vector"],
  ["filer_cvss40_score", "Filer CVSS 4.0 score"],
  ["filer_cvss40_band", "Filer CVSS 4.0 band"],
  ["nvd_cvss31_vector", "NVD CVSS 3.1 vector"],
  ["nvd_cvss31_score", "NVD CVSS 3.1 score"],
  ["nvd_cvss31_band", "NVD CVSS 3.1 band"],
  ["adp_cvss31_vector", "CISA ADP CVSS 3.1 vector"],
  ["adp_cvss31_score", "CISA ADP CVSS 3.1 score"],
  ["adp_cvss31_band", "CISA ADP CVSS 3.1 band"],
  ["ssvc_exploitation", "SSVC exploitation"],
  ["ssvc_automatable", "SSVC automatable"],
  ["ssvc_technical_impact", "SSVC technical impact"],
  ["kev_date_added", "Added to KEV"],
  ["kev_ransomware", "KEV ransomware use"],
  ["epss_score", "EPSS score"],
  ["epss_date", "EPSS score since"],
  ["exploit_first_seen", "First exploit code seen"],
  ["has_cpe", "NVD CPE configuration"],
];
const LABEL = new Map(FIELD_LABELS);
const ORDER = new Map(FIELD_LABELS.map(([k], i) => [k, i]));

export function fieldLabel(field: string): string {
  return LABEL.get(field) ?? field.replaceAll("_", " ");
}

export function toHealth(h: S["Health"]): Health {
  const db = h.database;
  return {
    statement: h.statement,
    status: h.status,
    database: db.reachable ? "ok" : db.configured ? "unreachable" : "not configured",
    data_version: h.data_version,
    version: h.version,
    release: h.data.tag ?? null,
    synced_at: h.data.last_sync?.at ?? h.data.loaded_at ?? null,
    generated_at: h.data.generated_at ?? null,
    storage: { used_bytes: db.database_size_bytes ?? null, ceiling_bytes: db.storage_ceiling_bytes, share: db.storage_share_used ?? null },
  };
}

/** Freshness per source from the locks the loaded bundle carries (GET /v1/meta); empty before a bundle is loaded. */
export function toFreshness(locks: Lock[] | null, now: number = Date.now()): SourceFreshness[] {
  if (!locks) return [];
  return locks.map((l) => {
    const at = l.fetched_at ? Date.parse(l.fetched_at) : NaN;
    const grace = GRACE[l.cadence] ?? GRACE.daily;
    return { source: l.source, fetched_at: l.fetched_at, cadence: l.cadence, stale: !Number.isFinite(at) || now - at > grace };
  });
}

function toLocks(locks: S["Meta"]["locks"]): Lock[] {
  return Object.entries(locks ?? {})
    .filter(([, v]) => isRecord(v))
    .map(([source, v]) => {
      const lock = v as Record<string, unknown>;
      return {
        source,
        digest: text(lock.lock_sha256) ?? text(lock.sha256) ?? "",
        files: num(lock.files) ?? 0,
        rows: num(lock.rows) ?? 0,
        fetched_at: text(lock.updated_at),
        cadence: text(lock.cadence) ?? "daily",
      };
    })
    .sort((a, b) => a.source.localeCompare(b.source));
}

function toLedger(rows: S["Meta"]["run_ledger"] | undefined): RunLedgerRow[] {
  return (rows ?? [])
    .filter(isRecord)
    .map((r) => ({
      source: text(r.source) ?? "",
      window: text(r.window) ?? "",
      rows_in: num(r.rows_in) ?? 0,
      rows_changed: num(r.rows_changed) ?? 0,
      digest: text(r.digest) ?? "",
      duration_s: num(r.duration_s) ?? 0,
      status: text(r.status) ?? "",
      finished_at: text(r.finished_at) ?? "",
      note: text(r.note),
    }))
    .reverse();
}

function toQuarantine(rows: S["Meta"]["quarantine"] | undefined): QuarantineCount[] {
  return (rows ?? [])
    .filter(isRecord)
    .map((r) => ({ rule: text(r.rule_id) ?? "", description: text(r.rule) ?? "", rows: num(r.rows) ?? 0, cves: num(r.cves) }));
}

export function toMeta(m: S["Meta"]): Meta {
  return {
    data_version: m.data_version,
    statement: m.statement,
    version: m.version,
    nvd_notice: m.nvd_notice,
    ghsa_attribution: m.attribution.join(" "),
    repository: m.repository,
    locks: toLocks(m.locks),
    run_ledger: toLedger(m.run_ledger),
    quarantine: toQuarantine(m.quarantine),
    bundle: m.bundle
      ? { tag: m.bundle.tag, generated_at: m.bundle.generated_at, lake_digest: m.bundle.lake_digest, files: m.bundle.files.map((f) => ({ file: f.file, sha256: f.sha256, rows: f.rows ?? null })) }
      : null,
    limits: m.limits
      ? {
          page_size_max: m.limits.page_size_max,
          sbom_upload_max_bytes: m.limits.sbom_upload_max_bytes,
          lookups_per_day: m.limits.lookups_per_day,
          matches_per_day: m.limits.matches_per_day,
          storage_ceiling_mb: m.limits.storage_ceiling_mb,
        }
      : null,
  };
}

function fieldValue(v: unknown): CveField["value"] {
  if (v === null || v === undefined) return null;
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") return v;
  if (Array.isArray(v)) return texts(v);
  return JSON.stringify(v);
}

export function toCve(r: S["CveRecord"]): Cve {
  const f = r.fields ?? {};
  const value = (name: string): unknown => f[name]?.value ?? null;
  const fields: CveField[] = Object.entries(f)
    .map(([field, fv]) => ({
      field,
      value: fieldValue(fv.value),
      source: fv.source ?? null,
      known_from: fv.known_from ?? null,
      dated_by: fv.rule,
    }))
    .sort((a, b) => (ORDER.get(a.field) ?? 99) - (ORDER.get(b.field) ?? 99) || a.field.localeCompare(b.field));
  return {
    data_version: r.data_version,
    statement: r.statement,
    id: r.cve_id,
    state: text(value("state")),
    as_of: r.as_of ?? null,
    known: r.known,
    note: r.note ?? null,
    published: text(value("published")),
    last_modified: text(value("last_modified")),
    filer: text(value("filer")),
    filer_type: text(value("filer_type")),
    nvd_status: text(value("nvd_status")),
    nvd_status_since: text(value("nvd_status_since")),
    description: text(value("description")),
    cve_org_url: r.links.cve_org ?? `https://www.cve.org/CVERecord?id=${r.cve_id}`,
    nvd_url: r.links.nvd ?? `https://nvd.nist.gov/vuln/detail/${r.cve_id}`,
    kev: { listed: text(value("kev_date_added")) !== null, date_added: text(value("kev_date_added")), ransomware: text(value("kev_ransomware")) },
    epss: { score: num(value("epss_score")), since: text(value("epss_date")) },
    fields,
  };
}

const ANALYZED = new Set(["Analyzed", "Modified"]);

function setsOf(detail: Record<string, unknown>): Record<string, unknown> {
  return isRecord(detail.sets) ? detail.sets : {};
}

/** The ruler's tick for one API event, or null for an event the ruler does not draw. */
export function toRulerEvent(e: S["TimelineEvent"]): TimelineEvent | null {
  const detail = isRecord(e.detail) ? e.detail : {};
  const sets = setsOf(detail);
  const source = e.source ?? "";
  const base = { at: e.at, source, analyzed: null as boolean | null };
  switch (e.kind) {
    case "published":
      return { ...base, kind: "published", value: null };
    case "nvd_status": {
      const status = text(sets.nvd_status) ?? text(detail.value) ?? text(detail.field === "nvd_status" ? detail.value : null);
      const analyzed = bool(detail.analyzed) ?? (status ? ANALYZED.has(status) : null);
      return { ...base, kind: "nvd_status", value: status, analyzed };
    }
    case "cvss31_vector":
    case "cvss40_vector":
    case "filer_score": {
      const filer = text(sets.filer_cvss31_vector) ?? text(sets.filer_cvss40_vector) ?? (e.kind === "filer_score" ? text(detail.vector) : null);
      if (filer) return { ...base, kind: "filer_score", value: filer };
      const adp = text(sets.adp_cvss31_vector);
      if (adp) return { ...base, kind: "cisa_adp", value: adp };
      return null;
    }
    case "ssvc": {
      const parts = [
        ["exploitation", sets.ssvc_exploitation],
        ["automatable", sets.ssvc_automatable],
        ["technical impact", sets.ssvc_technical_impact],
      ].filter(([, v]) => typeof v === "string");
      return { ...base, kind: "cisa_adp", value: parts.length ? `SSVC ${parts.map(([k, v]) => `${k} ${v}`).join(", ")}` : "SSVC" };
    }
    case "kev_listed":
      return { ...base, kind: "kev_listed", value: text(sets.kev_date_added) };
    case "exploit_code":
      return { ...base, kind: "exploit_code", value: text(detail.value) };
    case "cve_state":
      return text(sets.state) === "REJECTED" ? { ...base, kind: "rejected", value: null } : null;
    default:
      return null;
  }
}

const DAY = 86_400_000;

/** now is the moment an open wait is counted to: the time the page draws the ruler. */
export function toTimeline(t: S["Timeline"], now: string = new Date().toISOString()): Timeline {
  const published = t.published ?? null;
  // Offsets are calendar days in UTC, as the lake counts them (datediff on the two days).
  const dayOf = (iso: string) => {
    const t = Date.parse(iso);
    return Number.isFinite(t) ? Math.floor(t / DAY) : NaN;
  };
  const t0 = published ? dayOf(published) : NaN;
  const events = t.events.map(toRulerEvent).filter((e): e is TimelineEvent => e !== null);
  // The publication is the record's published time, not an event of the slice; the ruler starts there.
  if (published && !events.some((e) => e.kind === "published")) {
    events.unshift({ at: published, kind: "published", source: "CVE List", value: null, analyzed: null });
  }
  const epss: EpssOffset[] = t.events
    .filter((e) => e.kind === "epss" && isRecord(e.detail))
    .map((e) => {
      const at = dayOf(e.at);
      const raw = (e.detail as Record<string, unknown>).value;
      const score = typeof raw === "string" ? Number(raw) : num(raw);
      return {
        offset_days: Number.isFinite(t0) && Number.isFinite(at) ? at - t0 : 0,
        score: score !== null && Number.isFinite(score) ? score : null,
        score_date: e.at,
      };
    })
    .sort((a, b) => a.offset_days - b.offset_days);
  return { data_version: t.data_version, statement: t.statement, id: t.cve_id, now, published, events, epss };
}

export function toSummary(c: S["CveSummary"]): CveSummary {
  const v40 = c.filer_cvss40_score ?? null;
  return {
    id: c.cve_id,
    published: c.published ?? null,
    last_modified: c.last_modified ?? null,
    nvd_status: c.nvd_status ?? null,
    nvd_status_since: c.nvd_status_since ?? null,
    kev_listed: Boolean(c.kev_date_added),
    kev_date_added: c.kev_date_added ?? null,
    filer: c.filer ?? null,
    filer_type: c.filer_type ?? null,
    cwe: c.cwes ?? [],
    filer_cvss: v40 ?? c.filer_cvss31_score ?? null,
    filer_severity: (v40 !== null ? c.filer_cvss40_band : c.filer_cvss31_band) ?? null,
    epss: c.epss_score ?? null,
  };
}

export function toCveList(p: S["CvePage"]): CveList {
  return { data_version: p.data_version, statement: p.statement, items: p.items.map(toSummary), next_cursor: p.next_cursor ?? null };
}

function isQuestion(v: unknown): v is BacklogQuestion {
  if (!isRecord(v)) return false;
  return (
    typeof v.id === "string" &&
    typeof v.title === "string" &&
    Array.isArray(v.x) &&
    Array.isArray(v.series) &&
    (v.kind === "line" || v.kind === "bar") &&
    v.series.every((s) => isRecord(s) && Array.isArray(s.values) && s.values.length === (v.x as unknown[]).length)
  );
}

export function toBacklog(b: S["Backlog"]): Backlog {
  const doc = isRecord(b.backlog) ? b.backlog : {};
  const questions = Array.isArray(doc.questions) ? doc.questions.filter(isQuestion) : [];
  return { data_version: b.data_version, statement: b.statement, questions, data_cut: text(doc.data_cut) };
}

export function toProduct(p: S["Product"]): Product {
  const a = isRecord(p.attributes) ? p.attributes : {};
  return {
    id: p.product_id,
    name: p.name,
    what: text(a.what),
    ecosystem: text(a.ecosystem),
    kind: text(a.kind),
    stand_in: text(a.stand_in) ?? text(a.repository) ?? p.product_id,
    repository_url: text(a.repository_url),
    commit: text(a.commit),
    pinned_on: text(a.pinned_on),
    licence: text(a.licence),
    stars: num(a.stars),
    read_on: text(a.read_on),
  };
}

export function toProducts(p: S["Products"]): ProductList {
  return { data_version: p.data_version, statement: p.statement, items: p.products.map(toProduct) };
}

/** A finding body as the lake build or the matcher writes it, with the CVE state when the API gave one. */
function toFinding(body: Record<string, unknown>, cveIds: string[], states: Map<string, S["CveAsOf"]> | null): Finding {
  const matches = Array.isArray(body.matches) ? body.matches.filter(isRecord) : [];
  const first = matches[0] ?? {};
  const known = cveIds.map((id) => states?.get(id)).filter((s): s is S["CveAsOf"] => Boolean(s));
  return {
    component: text(body.component) ?? text(body.package) ?? "",
    version: text(body.version) ?? "",
    purl: text(body.purl),
    advisory_ids: texts(body.advisory_ids),
    cve_ids: cveIds,
    matched_range: text(body.matched_range) ?? text(first.matched_range),
    fixed: body.fixed !== undefined ? texts(body.fixed) : texts(body.fixed_versions),
    fix_available: bool(body.fix_available),
    source: text(body.source) ?? (texts(first.sources).join(", ") || text(first.source) || ""),
    advisory_known_from: text(body.advisory_known_from) ?? text(body.known_from),
    nvd_status: states ? (known.find((s) => s.nvd_status)?.nvd_status ?? null) : null,
    kev_listed: states ? known.some((s) => s.kev_listed) : null,
  };
}

function cvesOf(body: Record<string, unknown>): string[] {
  return [...new Set([...texts(body.cve_aliases), ...texts(body.upstream_cves)].filter((x) => x.startsWith("CVE-")))].sort();
}

export function toExposure(e: S["Exposure"]): Exposure {
  const states = new Map(e.cves.map((c) => [c.cve_id, c]));
  return {
    data_version: e.data_version,
    statement: e.statement,
    product_id: e.product.product_id,
    as_of: e.snapshot,
    snapshots: e.snapshots,
    findings: e.findings.map((f) => toFinding(isRecord(f.attributes) ? f.attributes : {}, f.cve_ids, states)),
    summary: {
      findings: e.summary.findings,
      distinct_cves: e.summary.distinct_cves,
      cves_kev_listed: e.summary.cves_kev_listed,
      cves_with_exploit_code: e.summary.cves_with_exploit_code,
      findings_fix_available: e.summary.findings_fix_available ?? null,
      cves_by_nvd_status: e.summary.cves_by_nvd_status,
    },
  };
}

const FORMAT_NAME: Record<string, string> = { cyclonedx: "CycloneDX", spdx: "SPDX" };

export function toMatch(m: S["MatchResponse"]): MatchResult {
  return {
    data_version: m.data_version,
    statement: m.statement,
    sbom_digest: m.sbom.sha256,
    format: [FORMAT_NAME[m.sbom.format] ?? m.sbom.format, m.sbom.spec_version].filter(Boolean).join(" "),
    components: m.sbom.components,
    without_purl: m.sbom.without_purl,
    findings: m.findings.filter(isRecord).map((f) => toFinding(f, cvesOf(f), null)),
    duration_ms: m.duration_ms,
    engine: m.engine,
  };
}
