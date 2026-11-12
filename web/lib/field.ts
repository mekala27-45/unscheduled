/**
 * The character field: one cell per day of new CVEs since 1 January 2024, on an 8 by 16 cell.
 * A row is a month; the character is the day's count on a density ramp, the tint is the share of
 * that day's CVEs the NVD analyzed within 30 days. Pure and deterministic: the same input always
 * gives the same field, so the hero can be tested without a browser.
 *
 * web/public/data/field.json is written by the data build. Its shape:
 *   { "source": string, "as_of": "YYYY-MM-DD", "from": "YYYY-MM-DD",
 *     "days": [{ "date": "YYYY-MM-DD", "published": number, "analyzed_30d": number | null }] }
 * analyzed_30d is a fraction of that day's CVEs, null until 30 days have passed.
 */

export type FieldDay = { date: string; published: number; analyzed_30d: number | null };
export type FieldData = { source: string; as_of: string; from: string; days: FieldDay[] };

/** 0 blank, 1 to 4 the glyph tints lightest to densest, 5 the accent-deep cells, 6 a row label. */
export type Tone = 0 | 1 | 2 | 3 | 4 | 5 | 6;
export type FieldCell = { ch: string; tone: Tone; day: number };
export type FieldRow = { month: string; cells: FieldCell[] };
export type FieldLayout = { rows: FieldRow[]; columns: number; cellsPerDay: 1 | 2; scaleMax: number };

export const RAMP = " .:-=+*#%@";
export const LABEL_CELLS = 8;
const ISO_DAY = /^\d{4}-\d{2}-\d{2}$/;

export function parseFieldData(value: unknown): FieldData | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  if (typeof v.source !== "string" || typeof v.as_of !== "string" || typeof v.from !== "string") return null;
  if (!Array.isArray(v.days)) return null;
  const days: FieldDay[] = [];
  for (const d of v.days) {
    if (typeof d !== "object" || d === null) return null;
    const r = d as Record<string, unknown>;
    if (typeof r.date !== "string" || !ISO_DAY.test(r.date)) return null;
    if (typeof r.published !== "number" || !Number.isFinite(r.published) || r.published < 0) return null;
    const share = r.analyzed_30d;
    if (share !== null && (typeof share !== "number" || share < 0 || share > 1)) return null;
    days.push({ date: r.date, published: r.published, analyzed_30d: share as number | null });
  }
  if (days.length === 0) return null;
  return { source: v.source, as_of: v.as_of, from: v.from, days };
}

/** The count that maps to the densest character: the 98th percentile, so one spike does not flatten the rest. */
export function scaleMaxOf(days: FieldDay[]): number {
  const counts = days.map((d) => d.published).filter((n) => n > 0).sort((a, b) => a - b);
  if (counts.length === 0) return 1;
  return Math.max(1, counts[Math.min(counts.length - 1, Math.floor(counts.length * 0.98))]);
}

export function levelFor(count: number, scaleMax: number): number {
  if (count <= 0) return 0;
  return Math.max(1, Math.min(RAMP.length - 1, Math.ceil((count / scaleMax) * (RAMP.length - 1))));
}

export function toneFor(share: number | null): Tone {
  if (share === null) return 1;
  if (share >= 0.75) return 5;
  if (share >= 0.5) return 4;
  if (share >= 0.25) return 3;
  if (share > 0) return 2;
  return 1;
}

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

export function layoutField(data: FieldData, cellsPerDay: 1 | 2): FieldLayout {
  const sorted = [...data.days].sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));
  const scaleMax = scaleMaxOf(sorted);
  const byMonth = new Map<string, Map<number, FieldDay>>();
  sorted.forEach((d) => {
    const month = d.date.slice(0, 7);
    if (!byMonth.has(month)) byMonth.set(month, new Map());
    byMonth.get(month)!.set(Number(d.date.slice(8, 10)), d);
  });
  const rows: FieldRow[] = [];
  let dayIndex = 0;
  for (const [month, days] of byMonth) {
    const cells: FieldCell[] = [];
    for (const ch of month.padEnd(LABEL_CELLS, " ")) cells.push({ ch, tone: ch === " " ? 0 : 6, day: -1 });
    const length = daysInMonth(Number(month.slice(0, 4)), Number(month.slice(5, 7)));
    for (let day = 1; day <= 31; day++) {
      const d = day <= length ? days.get(day) : undefined;
      if (!d) {
        for (let k = 0; k < cellsPerDay; k++) cells.push({ ch: " ", tone: 0, day: -1 });
        continue;
      }
      const level = levelFor(d.published, scaleMax);
      const tone = level === 0 ? 0 : toneFor(d.analyzed_30d);
      const index = sorted.indexOf(d, dayIndex);
      dayIndex = index;
      cells.push({ ch: RAMP[level], tone, day: index });
      if (cellsPerDay === 2) cells.push({ ch: RAMP[Math.max(0, level - 1)], tone: level > 1 ? tone : 0, day: index });
    }
    rows.push({ month, cells });
  }
  return { rows, columns: LABEL_CELLS + 31 * cellsPerDay, cellsPerDay, scaleMax };
}
