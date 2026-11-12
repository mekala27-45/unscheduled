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
    migration: "0001",
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
