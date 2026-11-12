/**
 * The system map on the landing page, drawn from the real system in section 4 of the Phase 1 plan:
 * sources into the lake, the lake into gold and the as-of engine, gold into the analysis, the match
 * and the API, the API into this console. Later phases sit on a dashed bottom row with their week, so
 * nothing unbuilt reads as built. The order of NODES is the reading order of the list shown under
 * 60rem and without script.
 */
export type Side = "top" | "right" | "bottom" | "left";

export type MapNode = {
  id: string;
  title: string;
  line: string;
  x: number;
  y: number;
  href?: string;
  linkText?: string;
  week?: number;
  lead?: boolean;
};

export type MapEdge = { from: string; to: string; out: Side; in: Side; later?: boolean };

export const COLUMN = 266;
export const NODE_WIDTH = 220;

export const NODES: MapNode[] = [
  {
    id: "sources",
    title: "Nine public sources",
    line: "Fetched in GitHub Actions, each locked by digest with its licence",
    x: 0,
    y: 0,
    href: "/app/data",
    linkText: "Sources and locks",
  },
  { id: "lake", title: "The lake", line: "Raw locks, bronze Parquet, silver facts that each carry known_from", x: COLUMN, y: 0 },
  {
    id: "gold",
    title: "Gold and the as-of engine",
    line: "The state of any CVE on any day, from facts known by then",
    x: COLUMN * 2,
    y: 0,
    href: "/app/cves",
    linkText: "Every CVE",
    lead: true,
  },
  { id: "api", title: "The API", line: "FastAPI on Vercel over a Neon slice, the statement in every response", x: COLUMN * 3, y: 0, href: "/status", linkText: "Its status, live" },
  { id: "console", title: "This console", line: "Search, the ruler, the backlog, the exposure, the match", x: COLUMN * 4, y: 0, href: "/app", linkText: "Open it" },
  { id: "analysis", title: "The backlog measured", line: "Q1 to Q8 with intervals, into the manifest", x: COLUMN * 2, y: 140, href: "/app/backlog", linkText: "The backlog" },
  { id: "match", title: "The match", line: "Syft SBOMs, exact version ranges, osv-scanner as the second engine", x: COLUMN * 3, y: 140, href: "/app/match", linkText: "Match an SBOM" },
  { id: "w2", title: "Models that fill the gaps", line: "Calibrated severity and exploitation, EPSS beside them", x: COLUMN, y: 280, week: 2 },
  { id: "w3", title: "An agent and an MCP server", line: "A patch plan and an early warning, every claim cited", x: COLUMN * 2, y: 280, week: 3 },
  { id: "w4", title: "Run as a service", line: "Kubernetes, Terraform, OpenTelemetry, a canary", x: COLUMN * 3, y: 280, week: 4 },
  { id: "w5", title: "The verdict", line: "Each criterion against its evidence, and the hand-over", x: COLUMN * 4, y: 280, week: 5 },
];

export const EDGES: MapEdge[] = [
  { from: "sources", to: "lake", out: "right", in: "left" },
  { from: "lake", to: "gold", out: "right", in: "left" },
  { from: "gold", to: "api", out: "right", in: "left" },
  { from: "api", to: "console", out: "right", in: "left" },
  { from: "gold", to: "analysis", out: "bottom", in: "top" },
  { from: "gold", to: "match", out: "right", in: "left" },
  { from: "match", to: "api", out: "top", in: "bottom" },
  { from: "lake", to: "w2", out: "bottom", in: "top", later: true },
  { from: "w2", to: "w3", out: "right", in: "left", later: true },
  { from: "w3", to: "w4", out: "right", in: "left", later: true },
  { from: "w4", to: "w5", out: "right", in: "left", later: true },
];

/** The first five nodes ink on, once, in reading order; the rest are drawn at rest. */
export const INK_ORDER = ["sources", "lake", "gold", "api", "console"];
