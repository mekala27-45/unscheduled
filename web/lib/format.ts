/** Dates print one way everywhere in the web app: 15 Apr 2026, in UTC. */
const DAY_MS = 86_400_000;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const MONTHS_LONG = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

export function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const d = new Date(/^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T00:00:00Z` : value);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatDate(value: string | Date | null | undefined, style: "short" | "long" = "short"): string {
  const d = value instanceof Date ? value : parseDate(value);
  if (!d) return "not recorded";
  const month = (style === "long" ? MONTHS_LONG : MONTHS)[d.getUTCMonth()];
  return `${d.getUTCDate()} ${month} ${d.getUTCFullYear()}`;
}

export function formatDateTime(value: string | null | undefined): string {
  const d = parseDate(value);
  if (!d) return "not recorded";
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  return `${formatDate(d)}, ${hh}:${mm} UTC`;
}

export function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** Whole days from a to b, rounded down. */
export function daysBetween(a: string | Date, b: string | Date): number {
  const x = a instanceof Date ? a : parseDate(a);
  const y = b instanceof Date ? b : parseDate(b);
  if (!x || !y) return 0;
  return Math.floor((y.getTime() - x.getTime()) / DAY_MS);
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${formatInt(n)} ${n === 1 ? one : many}`;
}

export function formatInt(n: number): string {
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 }).format(n);
}

/** A share stored as a fraction prints as a percent of its base. */
export function formatShare(n: number | null | undefined, decimals = 0): string {
  if (n == null || !Number.isFinite(n)) return "not known";
  return `${(n * 100).toFixed(decimals)}%`;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function shortDigest(digest: string, size = 12): string {
  const clean = digest.replace(/^sha256:/, "");
  return clean.length > size ? clean.slice(0, size) : clean;
}

export const DAY = DAY_MS;
