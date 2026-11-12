/**
 * The API contract, written by hand from section 12 of the Phase 1 prompt in the shape
 * openapi-typescript 7.13.0 emits, so the generated file replaces this one without touching a caller.
 * Regenerate once packages/api commits its OpenAPI 3.1 schema:
 *   pnpm dlx openapi-typescript@7.13.0 <path to openapi.json> -o lib/api/schema.ts
 *
 * Two filters on GET /v1/cves go past the section 12 list, for the console home's last 24 hours:
 * kev_added_from and analyzed_from. The API adds them or the home drops those two lists.
 * Status values are strings as the NVD returns them; nothing here assumes the vocabulary.
 */

type NoParams = { query?: never; header?: never; path?: never; cookie?: never };
type Unused = { put?: never; post?: never; delete?: never; options?: never; head?: never; patch?: never; trace?: never };
type Json<T> = { headers: { [name: string]: unknown }; content: { "application/json": T } };
type ProblemResponse = { headers: { [name: string]: unknown }; content: { "application/problem+json": components["schemas"]["Problem"] } };

export interface paths {
  "/health": { parameters: NoParams; get: operations["health"] } & Unused;
  "/v1/meta": { parameters: NoParams; get: operations["meta"] } & Unused;
  "/v1/cves": { parameters: NoParams; get: operations["listCves"] } & Unused;
  "/v1/cves/{id}": { parameters: NoParams; get: operations["getCve"] } & Unused;
  "/v1/cves/{id}/timeline": { parameters: NoParams; get: operations["getTimeline"] } & Unused;
  "/v1/backlog": { parameters: NoParams; get: operations["getBacklog"] } & Unused;
  "/v1/products": { parameters: NoParams; get: operations["listProducts"] } & Unused;
  "/v1/products/{id}/exposure": { parameters: NoParams; get: operations["getExposure"] } & Unused;
  "/v1/match": { parameters: NoParams; get?: never; post: operations["match"] } & Omit<Unused, "post">;
}

export type webhooks = Record<string, never>;

export interface components {
  schemas: {
    /** RFC 9457 problem document; every error the API returns is one. */
    Problem: {
      type: string;
      title: string;
      status: number;
      detail?: string | null;
      instance?: string | null;
    };
    /** Every response carries the data version and the statement. */
    ResponseMeta: {
      data_version: string;
      statement: string;
    };
    SourceFreshness: {
      source: string;
      fetched_at: string | null;
      cadence: string;
      stale: boolean;
    };
    /** The health stub of step one answers status, version, database and statement only; the rest arrives with the sync. */
    Health: {
      statement: string;
      status: string;
      database: string;
      data_version?: string;
      version?: string;
      release?: string | null;
      synced_at?: string | null;
      sources?: components["schemas"]["SourceFreshness"][];
    };
    Lock: {
      source: string;
      digest: string;
      size_bytes: number;
      url: string;
      fetched_at: string;
      licence: string;
      terms_read: string;
    };
    RunLedgerRow: {
      source: string;
      window: string;
      rows_in: number;
      rows_changed: number;
      digest: string;
      duration_s: number;
      status: string;
      finished_at: string;
    };
    QuarantineCount: {
      rule: string;
      description: string;
      rows: number;
    };
    Meta: components["schemas"]["ResponseMeta"] & {
      nvd_notice: string;
      ghsa_attribution: string;
      locks: components["schemas"]["Lock"][];
      run_ledger: components["schemas"]["RunLedgerRow"][];
      quarantine: components["schemas"]["QuarantineCount"][];
    };
    Kev: {
      listed: boolean;
      date_added: string | null;
      due_date: string | null;
      ransomware: string | null;
    };
    /** One value someone published about a CVE, with who published it and since when. */
    CveField: {
      field: string;
      value: string | number | boolean | null;
      source: string;
      known_from: string;
      /** The rule that dated it: event, publication or first fetch. */
      dated_by: string;
    };
    AffectedPackage: {
      ecosystem: string;
      name: string;
      purl: string | null;
      ranges: string[];
      fixed: string[];
      source: string;
    };
    EpssOffset: {
      offset_days: number;
      score: number | null;
      percentile: number | null;
      score_date: string | null;
      model_version: string | null;
    };
    Reference: {
      url: string;
      source: string;
      tags: string[];
    };
    CveSummary: {
      id: string;
      published: string;
      last_modified: string;
      nvd_status: string | null;
      kev_listed: boolean;
      kev_date_added: string | null;
      filer: string;
      filer_type: string | null;
      cwe: string[];
      filer_cvss: number | null;
      filer_severity: string | null;
    };
    CveList: components["schemas"]["ResponseMeta"] & {
      items: components["schemas"]["CveSummary"][];
      next_cursor: string | null;
    };
    Cve: components["schemas"]["ResponseMeta"] & {
      id: string;
      state: string;
      as_of: string | null;
      published: string;
      last_modified: string;
      filer: string;
      filer_type: string | null;
      nvd_status: string | null;
      nvd_status_since: string | null;
      description: string | null;
      cve_org_url: string;
      kev: components["schemas"]["Kev"];
      fields: components["schemas"]["CveField"][];
      affected: components["schemas"]["AffectedPackage"][];
      epss: components["schemas"]["EpssOffset"][];
      references: components["schemas"]["Reference"][];
    };
    TimelineEvent: {
      at: string;
      kind:
        | "published"
        | "filer_score"
        | "nvd_status"
        | "cisa_adp"
        | "kev_listed"
        | "exploit_code"
        | "ghsa_advisory"
        | "rejected";
      source: string;
      /** The value as the source gave it: a status, a vector, a GHSA id. */
      value: string | null;
      /** For nvd_status: whether config/labels.yaml registers this status as analyzed. */
      analyzed: boolean | null;
    };
    Timeline: components["schemas"]["ResponseMeta"] & {
      id: string;
      now: string;
      events: components["schemas"]["TimelineEvent"][];
    };
    BacklogSeries: {
      key: string;
      label: string;
      /** Slot in the fixed chart palette, 1 to 8. */
      slot: number;
      values: (number | null)[];
    };
    BacklogQuestion: {
      id: string;
      /** The one message of the chart, rendered from the manifest. */
      title: string;
      source: string;
      window: string;
      unit: string;
      kind: "line" | "bar";
      x: string[];
      series: components["schemas"]["BacklogSeries"][];
      rule: { x: string; label: string } | null;
      sql: string;
    };
    Backlog: components["schemas"]["ResponseMeta"] & {
      questions: components["schemas"]["BacklogQuestion"][];
    };
    Product: {
      id: string;
      name: string;
      ecosystem: string;
      stand_in: string;
      repository_url: string;
      commit: string;
      pinned_on: string;
      licence: string;
      stars: number;
      read_on: string;
    };
    ProductList: components["schemas"]["ResponseMeta"] & {
      items: components["schemas"]["Product"][];
    };
    Finding: {
      component: string;
      version: string;
      purl: string | null;
      advisory_ids: string[];
      cve_ids: string[];
      matched_range: string;
      fixed: string[];
      source: string;
      advisory_known_from: string;
      nvd_status: string | null;
      kev_listed: boolean;
    };
    Exposure: components["schemas"]["ResponseMeta"] & {
      product_id: string;
      as_of: string;
      findings: components["schemas"]["Finding"][];
    };
    MatchResult: components["schemas"]["ResponseMeta"] & {
      sbom_digest: string;
      format: string;
      components: number;
      findings: components["schemas"]["Finding"][];
    };
  };
  responses: never;
  parameters: never;
  requestBodies: never;
  headers: never;
  pathItems: never;
}

export type $defs = Record<string, never>;

export interface operations {
  health: {
    parameters: NoParams;
    requestBody?: never;
    responses: { 200: Json<components["schemas"]["Health"]>; default: ProblemResponse };
  };
  meta: {
    parameters: NoParams;
    requestBody?: never;
    responses: { 200: Json<components["schemas"]["Meta"]>; default: ProblemResponse };
  };
  listCves: {
    parameters: {
      query?: {
        published_from?: string;
        published_to?: string;
        nvd_status?: string;
        kev?: boolean;
        filer?: string;
        filer_type?: string;
        cwe?: string;
        has_filer_score?: boolean;
        kev_added_from?: string;
        analyzed_from?: string;
        cursor?: string;
        limit?: number;
      };
      header?: never;
      path?: never;
      cookie?: never;
    };
    requestBody?: never;
    responses: { 200: Json<components["schemas"]["CveList"]>; default: ProblemResponse };
  };
  getCve: {
    parameters: { query?: { as_of?: string }; header?: never; path: { id: string }; cookie?: never };
    requestBody?: never;
    responses: { 200: Json<components["schemas"]["Cve"]>; default: ProblemResponse };
  };
  getTimeline: {
    parameters: { query?: never; header?: never; path: { id: string }; cookie?: never };
    requestBody?: never;
    responses: { 200: Json<components["schemas"]["Timeline"]>; default: ProblemResponse };
  };
  getBacklog: {
    parameters: NoParams;
    requestBody?: never;
    responses: { 200: Json<components["schemas"]["Backlog"]>; default: ProblemResponse };
  };
  listProducts: {
    parameters: NoParams;
    requestBody?: never;
    responses: { 200: Json<components["schemas"]["ProductList"]>; default: ProblemResponse };
  };
  getExposure: {
    parameters: { query?: { as_of?: string }; header?: never; path: { id: string }; cookie?: never };
    requestBody?: never;
    responses: { 200: Json<components["schemas"]["Exposure"]>; default: ProblemResponse };
  };
  match: {
    parameters: NoParams;
    requestBody: { content: { "application/json": Record<string, unknown> } };
    responses: { 200: Json<components["schemas"]["MatchResult"]>; default: ProblemResponse };
  };
}
