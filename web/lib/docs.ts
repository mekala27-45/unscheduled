/**
 * The documents the site serves under /docs and /report, read from the repository when the site is
 * built and rendered from Markdown on the server. The site never edits one: each page is the file
 * at the commit the site was built from, and a file that is not there is not listed.
 * Server code only: these run in server components at build time.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { Marked, type Tokens } from "marked";

// Build time only, like lib/build-data.ts: every reader runs while static pages render.
const WEB_ROOT = existsSync(path.join(/*turbopackIgnore: true*/ process.cwd(), "next.config.ts")) ? process.cwd() : path.join(/*turbopackIgnore: true*/ process.cwd(), "web");
const REPO_ROOT = path.resolve(/*turbopackIgnore: true*/ WEB_ROOT, "..");

export type DocSection = "Start here" | "How it is built" | "Decisions" | "Runbooks" | "The data and the customer";
export const DOC_SECTIONS: DocSection[] = ["Start here", "How it is built", "Decisions", "Runbooks", "The data and the customer"];

/** A file the site renders; a report has no section, a document under /docs has one. */
export type DocSource = { slug: string; file: string; section?: DocSection };
export type TocEntry = { id: string; text: string };
export type Doc = DocSource & { title: string; lead: string; html: string; toc: TocEntry[] };

const FIXED_DOCS: DocSource[] = [
  { slug: "quickstart", file: "docs/quickstart.md", section: "Start here" },
  { slug: "api", file: "openapi.json", section: "Start here" },
  { slug: "architecture", file: "ARCHITECTURE.md", section: "How it is built" },
  { slug: "as-of", file: "docs/asof.md", section: "How it is built" },
  { slug: "methods", file: "docs/methods.md", section: "How it is built" },
  { slug: "spec", file: "docs/SPEC.md", section: "How it is built" },
  { slug: "roadmap", file: "docs/ROADMAP.md", section: "How it is built" },
  { slug: "provenance", file: "data/PROVENANCE.md", section: "The data and the customer" },
  { slug: "customer", file: "customer/README.md", section: "The data and the customer" },
];

/** An archify diagram shown at the top of a document, exported light and dark from its page. */
export type DocDiagram = { light: string; dark: string; page: string; width: number; height: number; alt: string; source: string };

const ARCHITECTURE: DocDiagram = {
  light: "/diagrams/architecture-light.svg",
  dark: "/diagrams/architecture-dark.svg",
  page: "/diagrams/architecture.html",
  width: 1610,
  height: 682,
  alt: "The architecture: nine sources fetched in Actions into raw, bronze, silver and gold layers, then the analysis, the match and the serving bundle the API pulls into Neon, and the web on top",
  source: "docs/diagrams/architecture.archify.json",
};

/** Which document opens with which diagram. */
export const DOC_DIAGRAMS: Record<string, DocDiagram> = {
  architecture: ARCHITECTURE,
  "as-of": {
    light: "/diagrams/status-light.svg",
    dark: "/diagrams/status-dark.svg",
    page: "/diagrams/status.html",
    width: 1314,
    height: 364,
    alt: "The NVD statuses as a lifecycle: Received, then Awaiting Analysis, Undergoing Analysis and Analyzed, with Modified after an analysis and back by Reanalysis, Deferred and Rejected below Received; Received, Analyzed, Modified and Rejected are dated by change history events, the other three by the first fetch that saw them",
    source: "docs/diagrams/status.archify.json",
  },
  methods: {
    light: "/diagrams/lineage-light.svg",
    dark: "/diagrams/lineage-dark.svg",
    page: "/diagrams/lineage.html",
    width: 1068,
    height: 740,
    alt: "Where every number comes from: bronze tables from the NVD, the CVE List, KEV, CISA ADP, EPSS and the exploit repositories become dated facts in silver, then cve_current and one mart per question in gold; the analysis writes the manifest the report and the site render from, the exposure run adds Q7 and the findings, and the serving bundle takes the CVE rows, the ruler events, the findings and the backlog charts",
    source: "docs/diagrams/lineage.archify.json",
  },
  "adr-0002": {
    light: "/diagrams/slice-light.svg",
    dark: "/diagrams/slice-dark.svg",
    page: "/diagrams/slice.html",
    width: 1548,
    height: 1178,
    alt: "The tables of the serving slice in Neon: cve, cve_event, product and finding, copied from the serving release, and settings, client_budget, match_log and ops_run, kept by the API itself, with every column and its type; cve_event names its CVE and finding its product by value, with no foreign key declared",
    source: "docs/diagrams/slice.archify.json",
  },
  "adr-0004": {
    light: "/diagrams/match-light.svg",
    dark: "/diagrams/match-dark.svg",
    page: "/diagrams/match.html",
    width: 920,
    height: 898,
    alt: "A match as a sequence: the console or curl posts one SBOM, the API charges the match budget in Neon, asks the OSV API for the advisories of its package names and ecosystems, fetches each record, checks every range with packages/match, logs the digest and the counts in Neon and answers with the findings",
    source: "docs/diagrams/match.archify.json",
  },
  "adr-0007": {
    light: "/diagrams/sync-light.svg",
    dark: "/diagrams/sync-dark.svg",
    page: "/diagrams/sync.html",
    width: 920,
    height: 1010,
    alt: "The sync as a sequence: lake.yml publishes the serving bundle, then calls the API, which takes an advisory lock in Neon, reads the newest serving release, downloads and checks one file, upserts one chunk and answers more, until a call answers done; a later call from the Vercel cron answers current",
    source: "docs/diagrams/sync.archify.json",
  },
};

export function architectureDiagram(): DocDiagram {
  return ARCHITECTURE;
}

/** The documents the build renders from the manifest, in reading order. */
export const REPORT_SOURCES: DocSource[] = [
  { slug: "backlog", file: "report/backlog.md" },
  { slug: "discovery", file: "report/discovery.md" },
  { slug: "legacy", file: "report/legacy.md" },
  { slug: "criteria", file: "report/criteria.md" },
  { slug: "data-card", file: "report/data_card.md" },
];

function exists(file: string): boolean {
  return existsSync(path.join(/*turbopackIgnore: true*/ REPO_ROOT, file));
}

function listFolder(folder: string, section: DocSection, prefix: string): DocSource[] {
  const dir = path.join(/*turbopackIgnore: true*/ REPO_ROOT, folder);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => name.endsWith(".md") && name !== "README.md")
    .sort()
    .map((name) => {
      const stem = name.replace(/\.md$/, "");
      const number = /^(\d{4})-/.exec(stem)?.[1];
      return { slug: number ? `${prefix}-${number}` : stem, file: `${folder}/${name}`, section };
    });
}

/** Every document /docs serves, fixed ones first, then the decision records and the runbooks as filed. */
export function docSources(): DocSource[] {
  return [...FIXED_DOCS, ...listFolder("docs/adr", "Decisions", "adr"), ...listFolder("docs/runbooks", "Runbooks", "runbook")].filter((d) => exists(d.file));
}

export function reportSources(): DocSource[] {
  return REPORT_SOURCES.filter((r) => exists(r.file));
}

function slugify(text: string): string {
  const s = text
    .toLowerCase()
    .replace(/<[^>]+>/g, "")
    .replace(/&[a-z#0-9]+;/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return s || "section";
}

/** Inline Markdown to plain text: code ticks and emphasis marks go, an underscore inside a name stays. */
function plain(text: string): string {
  return text
    .replace(/`/g, "")
    .replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/(^|\s)[*_](\S.*?)[*_](?=\s|[.,;:]|$)/g, "$1$2")
    .trim();
}

/**
 * The first sentence of the first paragraph, as the line under a document's name in a list. With
 * `from`, the paragraph is the first one under that second level heading (a decision record is
 * listed by its decision, not its context); a status line is never the lead.
 */
export function leadOf(markdown: string, from?: string): string {
  const start = from ? markdown.search(new RegExp(`^## ${from}\\s*$`, "m")) : -1;
  const blocks = (start >= 0 ? markdown.slice(start) : markdown).split(/\n\s*\n/).map((b) => b.trim());
  const first = blocks.find((b) => b && !/^(#|>|```|\||-\s|\*\s|\d+\.\s|<|Status:)/.test(b)) ?? "";
  const text = plain(first.replace(/\s+/g, " "));
  // The sentence ends at the first full stop or colon outside parentheses that a space or the end follows.
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "(") depth++;
    else if (c === ")") depth = Math.max(0, depth - 1);
    else if (depth === 0 && (c === "." || c === ":") && (i + 1 === text.length || text[i + 1] === " ")) {
      return `${text.slice(0, i)}.`;
    }
  }
  return text;
}

/**
 * Markdown to HTML with an id on every heading below the title, the second level collected as the
 * contents, and every table in a scrolling wrapper so a wide one never widens the page. The ids
 * follow GitHub's anchors, so one may start with a digit. The first level one heading is taken out
 * and returned as the title.
 */
export function renderMarkdown(markdown: string): { title: string | null; html: string; toc: TocEntry[] } {
  const used = new Map<string, number>();
  const toc: TocEntry[] = [];
  let title: string | null = null;
  const marked = new Marked({
    gfm: true,
    renderer: {
      heading(token: Tokens.Heading) {
        const text = plain(token.text);
        if (token.depth === 1 && title === null) {
          title = text;
          return "";
        }
        const base = slugify(text);
        const seen = used.get(base) ?? 0;
        used.set(base, seen + 1);
        const id = seen ? `${base}-${seen}` : base;
        if (token.depth === 2) toc.push({ id, text });
        const inner = this.parser.parseInline(token.tokens);
        return `<h${token.depth} id="${id}">${inner}</h${token.depth}>\n`;
      },
    },
  });
  // A box that may scroll sideways takes keyboard focus, so a reader without a pointer can scroll it.
  const html = (marked.parse(markdown, { async: false }) as string)
    .replaceAll("<table>", '<div class="doc__table" tabindex="0"><table>')
    .replaceAll("</table>", "</table></div>")
    .replaceAll("<pre>", '<pre tabindex="0">');
  return { title, html, toc };
}

type Schema = { type?: string | string[]; format?: string; enum?: unknown[]; anyOf?: Schema[]; items?: Schema; $ref?: string };
type Parameter = { name: string; in: string; required?: boolean; description?: string; schema?: Schema };
type Operation = {
  summary?: string;
  tags?: string[];
  parameters?: Parameter[];
  requestBody?: { content?: Record<string, unknown>; description?: string };
  responses?: Record<string, { description?: string }>;
};
type OpenApi = { info: { title: string; version: string; summary?: string }; paths: Record<string, Record<string, Operation>> };

const TAG_ORDER = ["service", "cves", "backlog", "exposure", "match", "legacy", "sync"];
const METHODS = ["get", "post", "put", "patch", "delete"];

function typeOf(schema: Schema | undefined): string {
  if (!schema) return "";
  if (schema.anyOf) return schema.anyOf.map(typeOf).filter((t) => t && t !== "null").join(" or ");
  if (schema.enum) return schema.enum.map(String).join(", ");
  if (schema.$ref) return schema.$ref.split("/").pop() ?? "";
  const base = Array.isArray(schema.type) ? schema.type.filter((t) => t !== "null").join(" or ") : (schema.type ?? "");
  return schema.format ? `${base} (${schema.format})` : base;
}

function cell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\s+/g, " ").trim();
}

/**
 * The API reference as Markdown, from the committed openapi.json: every route with its summary, its
 * parameters, its request body and the answers it documents, grouped as the API tags them.
 */
export function openApiMarkdown(spec: OpenApi): string {
  const lines = [
    "# API reference",
    "",
    `The API at https://unscheduled-api.vercel.app, version ${spec.info.version}, read from openapi.json at the root of the repository when this site was built. CI fails when the schema the API generates and the committed file differ, and the console's typed client is generated from the same file.`,
    "",
    "No key is needed. Each client has a daily budget of lookups and SBOM matches (config/budgets.yaml), and every data answer says what is left in X-Budget-Remaining. Every answer carries the statement and the data version; every error is a problem document whose type links to its entry in docs/SPEC.md.",
    "",
  ];
  const operations = Object.entries(spec.paths).flatMap(([route, ops]) =>
    METHODS.filter((m) => ops[m]).map((m) => ({ route, method: m.toUpperCase(), op: ops[m] })),
  );
  const rank = (op: Operation) => {
    const i = TAG_ORDER.indexOf(op.tags?.[0] ?? "");
    return i < 0 ? TAG_ORDER.length : i;
  };
  operations.sort((a, b) => rank(a.op) - rank(b.op) || a.route.localeCompare(b.route) || a.method.localeCompare(b.method));
  for (const { route, method, op } of operations) {
    lines.push(`## ${method} ${route}`, "", `${op.summary ?? ""}.`, "");
    const params = op.parameters ?? [];
    if (params.length) {
      lines.push("| Parameter | In | Required | Type | What it means |", "|---|---|---|---|---|");
      for (const p of params) {
        lines.push(`| ${p.name} | ${p.in} | ${p.required ? "yes" : "no"} | ${cell(typeOf(p.schema))} | ${cell(p.description ?? "")} |`);
      }
      lines.push("");
    }
    const media = Object.keys(op.requestBody?.content ?? {});
    if (media.length) lines.push(`Body: ${media.join(", ")}${op.requestBody?.description ? `; ${op.requestBody.description}` : ""}.`, "");
    const answers = Object.entries(op.responses ?? {});
    if (answers.length) {
      lines.push("| Answer | When |", "|---|---|");
      for (const [code, r] of answers) lines.push(`| ${code} | ${cell(r.description ?? "")} |`);
      lines.push("");
    }
  }
  return lines.join("\n");
}

function load(source: DocSource): Doc | null {
  const file = path.join(/*turbopackIgnore: true*/ REPO_ROOT, source.file);
  if (!existsSync(file)) return null;
  const raw = readFileSync(file, "utf8");
  const markdown = source.file.endsWith(".json") ? openApiMarkdown(JSON.parse(raw) as OpenApi) : raw;
  const rendered = renderMarkdown(markdown);
  const lead = leadOf(markdown, source.section === "Decisions" ? "Decision" : undefined);
  return { ...source, title: rendered.title ?? source.file, lead, html: rendered.html, toc: rendered.toc };
}

export function readDoc(slug: string): Doc | null {
  const source = docSources().find((d) => d.slug === slug);
  return source ? load(source) : null;
}

export function readDocs(): Doc[] {
  return docSources()
    .map(load)
    .filter((d): d is Doc => d !== null);
}

export function readReport(slug: string): Doc | null {
  const source = reportSources().find((r) => r.slug === slug);
  return source ? load(source) : null;
}

export function readReports(): Doc[] {
  return reportSources()
    .map(load)
    .filter((d): d is Doc => d !== null);
}
