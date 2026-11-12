import createClient, { type Client } from "openapi-fetch";
import type { components, paths } from "./schema";

export type Schemas = components["schemas"];
export type Problem = Schemas["Problem"];
export type Health = Schemas["Health"];
export type Meta = Schemas["Meta"];
export type Cve = Schemas["Cve"];
export type CveSummary = Schemas["CveSummary"];
export type CveList = Schemas["CveList"];
export type Timeline = Schemas["Timeline"];
export type TimelineEvent = Schemas["TimelineEvent"];
export type Backlog = Schemas["Backlog"];
export type BacklogQuestion = Schemas["BacklogQuestion"];
export type ProductList = Schemas["ProductList"];
export type Product = Schemas["Product"];
export type Exposure = Schemas["Exposure"];
export type Finding = Schemas["Finding"];
export type MatchResult = Schemas["MatchResult"];
export type CveQuery = NonNullable<paths["/v1/cves"]["get"]["parameters"]["query"]>;

/** Why a request did not produce data; each kind has its own error state in the console. */
export type ApiErrorKind = "not-configured" | "network" | "http" | "invalid";

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly path: string;
  readonly status: number | null;
  readonly problem: Problem | null;

  constructor(kind: ApiErrorKind, path: string, message: string, status: number | null = null, problem: Problem | null = null) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.path = path;
    this.status = status;
    this.problem = problem;
  }
}

/** The API origin, read from NEXT_PUBLIC_API_URL when the site is built. */
export const API_BASE: string | null = (() => {
  const raw = process.env.NEXT_PUBLIC_API_URL;
  if (!raw) return null;
  try {
    const url = new URL(raw);
    return url.toString().replace(/\/+$/, "");
  } catch {
    return null;
  }
})();

export const MATCH_LIMIT_BYTES = 2 * 1024 * 1024;

let client: Client<paths> | null = null;

function getClient(path: string): Client<paths> {
  if (!API_BASE) {
    throw new ApiError("not-configured", path, "This build has no API address.");
  }
  client ??= createClient<paths>({ baseUrl: API_BASE });
  return client;
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const hasArrays = (v: unknown, ...keys: string[]): boolean => isRecord(v) && keys.every((k) => Array.isArray(v[k]));
const hasStrings = (v: unknown, ...keys: string[]): boolean => isRecord(v) && keys.every((k) => typeof v[k] === "string");

function isProblem(v: unknown): v is Problem {
  return isRecord(v) && typeof v.title === "string" && typeof v.status === "number";
}

type Outcome<T> = { data?: T; error?: unknown; response: Response };

async function run<T>(path: string, request: (c: Client<paths>) => Promise<Outcome<T>>, check: (v: unknown) => boolean): Promise<T> {
  const c = getClient(path);
  let outcome: Outcome<T>;
  try {
    outcome = await request(c);
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    throw new ApiError("network", path, "The API did not answer.");
  }
  const { data, error, response } = outcome;
  if (!response.ok) {
    const problem = isProblem(error) ? error : null;
    throw new ApiError("http", path, problem?.title ?? (response.statusText || `HTTP ${response.status}`), response.status, problem);
  }
  if (!check(data)) {
    throw new ApiError("invalid", path, "The API answered with a shape this page does not read.");
  }
  return data as T;
}

const meta = (v: unknown) => hasStrings(v, "data_version", "statement");

/** The stub's /v1/meta keeps locks in an object and has no ledger yet: read what is there, an absent list as empty. */
function normalizeMeta(v: unknown): Meta | null {
  if (!isRecord(v) || typeof v.statement !== "string") return null;
  const list = <T,>(x: unknown): T[] => (Array.isArray(x) ? (x as T[]) : []);
  return {
    data_version: typeof v.data_version === "string" ? v.data_version : typeof v.version === "string" ? v.version : "not reported",
    statement: v.statement,
    nvd_notice: typeof v.nvd_notice === "string" ? v.nvd_notice : "",
    ghsa_attribution: typeof v.ghsa_attribution === "string" ? v.ghsa_attribution : "",
    locks: list(v.locks),
    run_ledger: list(v.run_ledger),
    quarantine: list(v.quarantine),
  };
}

export const api = {
  health: (signal?: AbortSignal) =>
    run<Health>("/health", (c) => c.GET("/health", { signal }), (v) => hasStrings(v, "status", "statement")),

  meta: async (signal?: AbortSignal) => {
    const raw = await run<unknown>("/v1/meta", (c) => c.GET("/v1/meta", { signal }), (v) => normalizeMeta(v) !== null);
    return normalizeMeta(raw) as Meta;
  },

  cves: (query: CveQuery, signal?: AbortSignal) =>
    run<CveList>("/v1/cves", (c) => c.GET("/v1/cves", { params: { query }, signal }), (v) => meta(v) && hasArrays(v, "items")),

  cve: (id: string, asOf: string | null, signal?: AbortSignal) =>
    run<Cve>(
      `/v1/cves/${id}`,
      (c) => c.GET("/v1/cves/{id}", { params: { path: { id }, query: asOf ? { as_of: asOf } : {} }, signal }),
      (v) => meta(v) && hasStrings(v, "id", "published") && hasArrays(v, "fields", "affected", "epss", "references"),
    ),

  timeline: (id: string, signal?: AbortSignal) =>
    run<Timeline>(
      `/v1/cves/${id}/timeline`,
      (c) => c.GET("/v1/cves/{id}/timeline", { params: { path: { id } }, signal }),
      (v) => meta(v) && hasStrings(v, "id", "now") && hasArrays(v, "events"),
    ),

  backlog: (signal?: AbortSignal) =>
    run<Backlog>("/v1/backlog", (c) => c.GET("/v1/backlog", { signal }), (v) => meta(v) && hasArrays(v, "questions")),

  products: (signal?: AbortSignal) =>
    run<ProductList>("/v1/products", (c) => c.GET("/v1/products", { signal }), (v) => meta(v) && hasArrays(v, "items")),

  exposure: (id: string, asOf: string | null, signal?: AbortSignal) =>
    run<Exposure>(
      `/v1/products/${id}/exposure`,
      (c) => c.GET("/v1/products/{id}/exposure", { params: { path: { id }, query: asOf ? { as_of: asOf } : {} }, signal }),
      (v) => meta(v) && hasArrays(v, "findings"),
    ),

  match: (sbom: Record<string, unknown>, signal?: AbortSignal) =>
    run<MatchResult>(
      "/v1/match",
      (c) => c.POST("/v1/match", { body: sbom, signal }),
      (v) => meta(v) && hasStrings(v, "sbom_digest") && hasArrays(v, "findings"),
    ),
};

/** What to tell a person about a failed request: what broke and what to do next. */
export function describeError(error: unknown): { title: string; body: string; detail: string | null; retry: boolean } {
  // An ApiError that crossed from a server component arrives as a plain object; read it by its kind.
  if (!(error instanceof ApiError) && isRecord(error) && typeof error.kind === "string" && typeof error.path === "string") {
    const status = typeof error.status === "number" ? error.status : null;
    error = new ApiError(error.kind as ApiErrorKind, error.path, String(error.message ?? ""), status, isProblem(error.problem) ? error.problem : null);
  }
  if (error instanceof ApiError) {
    switch (error.kind) {
      case "not-configured":
        return {
          title: "This build has no API address",
          body: "The console reads every value from the unscheduled API. Set NEXT_PUBLIC_API_URL for the web project and build it again.",
          detail: null,
          retry: false,
        };
      case "network":
        return {
          title: "The API did not answer",
          body: "It may be waking from idle, which takes a few seconds on the free tier. Try again; if it fails twice, the status page shows which part is down.",
          detail: `${API_BASE ?? ""}${error.path}`,
          retry: true,
        };
      case "http":
        if (error.status === 404 && !error.problem) {
          return {
            title: "The API has no data for this yet",
            body: "It answered 404 for this request. The endpoint is not deployed, or no data release has been loaded into it.",
            detail: `GET ${error.path} answered 404`,
            retry: true,
          };
        }
        return {
          title: error.problem?.title ?? `The API answered ${error.status ?? "an error"}`,
          body: error.problem?.detail ?? "The request reached the API and was refused. Try again; the status page says whether the data is current.",
          detail: `${error.path} answered ${error.status ?? "an error"}${error.problem?.type ? `, ${error.problem.type}` : ""}`,
          retry: (error.status ?? 500) >= 500 || error.status === 429,
        };
      case "invalid":
        return {
          title: "The answer did not match the contract",
          body: "The API answered, but not in the shape this page reads. One of the two is older than the other; the web client is regenerated from the API's OpenAPI schema.",
          detail: error.path,
          retry: false,
        };
    }
  }
  return { title: "Something failed in this page", body: "Reload the page. If it fails again, the status page says which part is down.", detail: null, retry: true };
}
