/**
 * FIXTURE. Invented answers in the API's own shape (lib/api/openapi.ts), for the Playwright mocks,
 * and adapted by lib/api/adapt.ts into the view fixtures of lib/fixtures/cve.ts for the unit tests
 * and the /design specimen. CVE-2099-0001 does not exist, the filer is example.com, and the data
 * version says "fixture" so every page that shows these values says so. Nothing here is data.
 */
import type { components } from "../api/openapi";
import { STATEMENT } from "../statement";

type S = components["schemas"];

export const FIXTURE_ID = "CVE-2099-0001";
const V = { data_version: "fixture", statement: STATEMENT };

const field = (value: S["FieldValue"]["value"], source: string | null, known_from: string | null, rule: string): S["FieldValue"] => ({
  value,
  source,
  known_from,
  rule,
});

export const API_CVE: S["CveRecord"] = {
  ...V,
  cve_id: FIXTURE_ID,
  as_of: null,
  known: true,
  note: null,
  links: { cve_org: `https://www.cve.org/CVERecord?id=${FIXTURE_ID}`, nvd: `https://nvd.nist.gov/vuln/detail/${FIXTURE_ID}` },
  fields: {
    state: field("PUBLISHED", "example.com", "2026-03-02T14:05:00Z", "publication"),
    published: field("2026-03-02T14:05:00Z", "example.com", "2026-03-02T14:05:00Z", "publication"),
    last_modified: field("2026-06-30T00:00:00Z", "cvelist", "2026-06-30T00:00:00Z", "last change seen"),
    filer: field("example.com", "example.com", "2026-03-02T14:05:00Z", "publication"),
    filer_type: field("vendor", "example.com", "2026-03-02T14:05:00Z", "publication"),
    description: field(
      "Fixture text standing in for a CNA description: an example service accepts a crafted request and runs it.",
      "example.com",
      "2026-03-02T14:05:00Z",
      "the current text of the CVE record",
    ),
    nvd_status: field("Awaiting Analysis", "nvd@nist.gov", "2026-03-24T00:00:00Z", "event nvd_status, nvd_history"),
    nvd_status_since: field("2026-03-24T00:00:00Z", "nvd@nist.gov", "2026-03-24T00:00:00Z", "event nvd_status, nvd_history"),
    cwes: field(["CWE-94"], "example.com", "2026-03-02T14:05:00Z", "record_updated"),
    filer_cvss31_vector: field("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "example.com", "2026-03-02T14:05:00Z", "event cvss31_vector, record_updated"),
    filer_cvss31_score: field(9.8, "example.com", "2026-03-02T14:05:00Z", "event cvss31_vector, record_updated"),
    filer_cvss31_band: field("Critical", "example.com", "2026-03-02T14:05:00Z", "event cvss31_vector, record_updated"),
    ssvc_exploitation: field("poc", "CISA-ADP", "2026-03-11T08:30:00Z", "event ssvc, git_commit"),
    kev_date_added: field("2026-06-30", "kev", "2026-06-30T00:00:00Z", "event kev_listed, kev_date_added"),
    kev_ransomware: field("Unknown", "kev", "2026-06-30T00:00:00Z", "event kev_ransomware, kev_date_added"),
    epss_score: field(0.052, "epss", "2026-04-01T00:00:00Z", "epss_score_date"),
    epss_date: field("2026-04-01", "epss", "2026-04-01T00:00:00Z", "epss_score_date"),
    exploit_first_seen: field("2026-05-19", "nuclei", "2026-05-19T21:47:00Z", "event exploit_code, git_first_commit"),
  },
  predictions: {
    batch: "fixture00000",
    made_on: "2026-11-14",
    window: "test",
    note: "Predictions of the Phase 2 models, never NVD values. FIXTURE: invented values in the API's shape.",
    values: [
      {
        field: "band",
        model: "unscheduled-band",
        version: 3,
        role: "model",
        value: "CRITICAL",
        probability: 0.62,
        probabilities: { LOW: 0.02, MEDIUM: 0.07, HIGH: 0.29, CRITICAL: 0.62 },
        set: ["HIGH", "CRITICAL"],
      },
      ...(["AV", "AC", "PR", "UI", "S", "C", "I", "A"] as const).map((m, i) => ({
        field: `metric_${m}`,
        model: "unscheduled-metrics",
        version: 3,
        role: "model",
        value: ["N", "L", "N", "N", "U", "H", "H", "H"][i],
        probability: 0.81 - i * 0.03,
        set: m === "PR" ? ["N", "L"] : [["N", "L", "N", "N", "U", "H", "H", "H"][i]],
      })),
      { field: "cwe", model: "unscheduled-cwe", version: 3, role: "model", value: "CWE-94", probability: 0.34, detail: { top5: ["CWE-94", "CWE-78", "CWE-77", "CWE-20", "other"] } },
      {
        field: "exploitation",
        model: "unscheduled-exploit",
        version: 2,
        role: "model",
        value: 0.041,
        probability: 0.041,
        detail: {
          score: 0.18,
          percentile: 99.2,
          percentile_of: "every CVE in batch fixture00000",
          epss: { score: 0.052, percentile: 0.91, date: "2026-04-01", note: "EPSS from FIRST, beside the model and not compared with it here." },
        },
      },
      { field: "kev_listing", model: "unscheduled-survival", version: 1, role: "floor", value: { "30": 0.011, "90": 0.024, "180": 0.033 } },
      { field: "products", model: "unscheduled-product", version: 2, role: "model", value: ["example:service", "example:gateway"] },
    ],
  },
  predictions_note: null,
};

export const API_MODELS: S["ModelsDocument"] = {
  ...V,
  note: "FIXTURE: invented values in the API's shape.",
  models: {
    batch: "fixture00000",
    made_on: "2026-11-14",
    models: [
      {
        name: "unscheduled-band",
        description: "The NVD CVSS 3.1 severity band of a CVE at day 0.",
        chosen_by: "config/operating_points.yaml, primary",
        aliases: { chosen: 3, scored: 3 },
        versions: [
          { version: 1, role: "floor", stage: "scored", description: "TF-IDF beside the filer and CISA block", dev: { qwk: 0.701 }, test: { qwk: 0.684 } },
          { version: 2, role: "ablation", stage: "scored", description: "frozen embeddings alone", dev: { qwk: 0.512 }, test: { qwk: 0.497 } },
          { version: 3, role: "model", stage: "scored", description: "frozen embeddings beside the block", dev: { qwk: 0.716 }, test: { qwk: 0.69 } },
        ],
      },
    ],
    evidence: {
      c1: {
        verdict: "not met",
        population: "test window CVEs with an NVD CVSS 3.1 band",
        kappa: {
          rows: 40264,
          clusters: 310,
          model: { value: 0.69, low: 0.66, high: 0.72 },
          floor: { value: 0.684, low: 0.65, high: 0.71 },
          difference: { value: 0.006, low: -0.004, high: 0.016, p: 0.24 },
        },
        ece: { value: 0.031, low: 0.022, high: 0.044 },
        reliability: [
          { low: 0.33, high: 0.4, rows: 900, confidence: 0.37, accuracy: 0.34 },
          { low: 0.53, high: 0.6, rows: 4200, confidence: 0.57, accuracy: 0.55 },
          { low: 0.8, high: 0.87, rows: 9000, confidence: 0.84, accuracy: 0.8 },
          { low: 0.93, high: 1, rows: 15000, confidence: 0.96, accuracy: 0.93 },
        ],
      },
      c2: {
        verdict: "met",
        note: "EPSS at days 7 and 30 has seen days the model has not",
        recall_at_top5: {
          rows: 63000,
          positives: 120,
          top: 3150,
          model: { value: 0.61, low: 0.52, high: 0.7 },
          epss_day_1: { value: 0.49, low: 0.4, high: 0.58 },
          model_minus_epss_day_1: { value: 0.12, low: 0.03, high: 0.21, reading: "ahead" },
        },
      },
      taxonomy: { categories: [{ name: "The filer score disagrees with the NVD", count: 31, meaning: "the vector the filer gave led the model one band away" }] },
    },
  },
};

const event = (at: string, kind: string, source: string, detail: Record<string, unknown>, n: number): S["TimelineEvent"] => ({
  event_id: `fixture${String(n).padStart(9, "0")}`,
  at,
  kind,
  source,
  detail,
});

export const API_TIMELINE: S["Timeline"] = {
  ...V,
  cve_id: FIXTURE_ID,
  published: "2026-03-02T14:05:00Z",
  events: [
    event(
      "2026-03-02T14:05:00Z",
      "cvss31_vector",
      "example.com",
      { dated_by: "record_updated", sets: { filer_cvss31_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", filer_cvss31_score: 9.8, filer_cvss31_band: "Critical" } },
      2,
    ),
    event("2026-03-02T16:40:00Z", "nvd_status", "nvd@nist.gov", { dated_by: "nvd_history", sets: { nvd_status: "Received" } }, 3),
    event("2026-03-02T16:40:00Z", "epss", "epss", { value: "0.004", dated_by: "epss_score_date" }, 4),
    event("2026-03-11T08:30:00Z", "ssvc", "CISA-ADP", { dated_by: "git_commit", sets: { ssvc_exploitation: "poc", ssvc_automatable: "no", ssvc_technical_impact: "total" } }, 5),
    event("2026-03-24T00:00:00Z", "nvd_status", "nvd@nist.gov", { dated_by: "nvd_history", sets: { nvd_status: "Awaiting Analysis" } }, 6),
    event("2026-04-01T00:00:00Z", "epss", "epss", { value: "0.052", dated_by: "epss_score_date" }, 7),
    event("2026-05-19T21:47:00Z", "exploit_code", "nuclei", { value: "http/cves/2099/CVE-2099-0001.yaml", dated_by: "git_first_commit", sets: { exploit_first_seen: "2026-05-19" } }, 8),
    event("2026-06-30T00:00:00Z", "kev_listed", "kev", { dated_by: "kev_date_added", sets: { kev_date_added: "2026-06-30" } }, 9),
    event("2026-06-30T00:00:00Z", "kev_ransomware", "kev", { dated_by: "kev_date_added", sets: { kev_ransomware: "Unknown" } }, 10),
  ],
};

const summary = (s: Partial<S["CveSummary"]> & { cve_id: string }): S["CveSummary"] => ({
  cwes: [],
  epss_score: null,
  exploit_first_seen: null,
  filer: null,
  filer_cvss31_band: null,
  filer_cvss31_score: null,
  filer_cvss40_band: null,
  filer_cvss40_score: null,
  filer_type: null,
  has_cpe: null,
  kev_date_added: null,
  last_modified: null,
  nvd_cvss31_band: null,
  nvd_cvss31_score: null,
  nvd_status: null,
  nvd_status_since: null,
  published: null,
  ...s,
});

export const API_SUMMARIES: S["CveSummary"][] = [
  summary({ cve_id: "CVE-2099-0001", published: "2026-03-02T14:05:00Z", last_modified: "2026-06-30T00:00:00Z", nvd_status: "Awaiting Analysis", kev_date_added: "2026-06-30", filer: "example.com", filer_type: "vendor", cwes: ["CWE-94"], filer_cvss31_score: 9.8, filer_cvss31_band: "Critical" }),
  summary({ cve_id: "CVE-2099-0002", published: "2026-04-21T10:00:00Z", last_modified: "2026-04-22T10:00:00Z", nvd_status: "Received", filer: "example.org", filer_type: "open source project", cwes: ["CWE-79"], filer_cvss31_score: 6.1, filer_cvss31_band: "Medium" }),
  summary({ cve_id: "CVE-2099-0003", published: "2026-05-08T08:00:00Z", last_modified: "2026-05-30T08:00:00Z", nvd_status: "Analyzed", filer: "example.net", filer_type: "research or bug bounty platform", cwes: ["CWE-22"], filer_cvss40_score: 7.5, filer_cvss40_band: "High" }),
  summary({ cve_id: "CVE-2099-0004", published: "2026-06-14T12:30:00Z", last_modified: "2026-06-14T12:30:00Z", filer: "example.com", filer_type: "vendor" }),
];

export const apiPage = (items: S["CveSummary"][] = API_SUMMARIES, next: string | null = null): S["CvePage"] => ({
  ...V,
  items,
  next_cursor: next,
  limit: 100,
  filters: {},
});

/** The API before a bundle is loaded: reachable, empty, honest about it. */
export const API_HEALTH_EMPTY: S["Health"] = {
  ...V,
  data_version: "none loaded",
  status: "ok",
  version: "0.1.0",
  ready: false,
  database: {
    configured: true,
    variable: "DATABASE_URL",
    variables_found: ["DATABASE_URL"],
    reachable: true,
    schema_name: "unscheduled",
    migration: "0002",
    server_version: "18.6",
    pgvector_available: true,
    pgvector_installed: false,
    database_size_bytes: 8_100_000,
    storage_ceiling_mb: 800,
    storage_ceiling_bytes: 800_000_000,
    storage_share_used: 0.01,
    error: null,
  },
  data: {
    counts: null,
    data_version: "none loaded",
    freshness: null,
    generated_at: null,
    lake_digest: null,
    last_sync: null,
    loaded_at: null,
    loading: null,
    sources: null,
    tag: null,
  },
  release: { checked_at: null, newest: null, repository: "mekala27-45/unscheduled", tag_prefix: "serving-" },
};

export const API_META_EMPTY: S["Meta"] = {
  ...V,
  data_version: "none loaded",
  version: "0.1.0",
  nvd_notice: "This product uses the NVD API but is not endorsed or certified by the NVD.",
  attribution: ["GitHub Advisory Database, CC BY 4.0"],
  repository: "mekala27-45/unscheduled",
  locks: {},
  bundle: null,
  limits: {
    page_size_max: 100,
    sbom_upload_max_bytes: 2_097_152,
    lookups_per_day: 2000,
    matches_per_day: 50,
    sync_calls_per_minute: 30,
    storage_ceiling_mb: 800,
  },
  quarantine: [],
  run_ledger: [],
};
