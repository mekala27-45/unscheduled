import { describe, expect, it } from "vitest";
import { layoutField, levelFor, parseFieldData, RAMP, scaleMaxOf, toneFor, type FieldData } from "@/lib/field";

// FIXTURE: invented daily counts for the field generator; not CVE data.
function fixture(): FieldData {
  const days = [];
  const start = Date.UTC(2026, 2, 1);
  for (let i = 0; i < 92; i++) {
    const date = new Date(start + i * 86_400_000).toISOString().slice(0, 10);
    days.push({ date, published: 40 + ((i * 37) % 90), analyzed_30d: date < "2026-04-15" ? 0.8 : 0.1 });
  }
  return { source: "fixture", as_of: "2026-06-01", from: "2026-03-01", days };
}

describe("the character field", () => {
  it("gives the same field for the same input, whatever the order of the days", () => {
    const a = fixture();
    const b = { ...a, days: [...a.days].reverse() };
    expect(layoutField(a, 2)).toEqual(layoutField(b, 2));
  });

  it("lays out a row per month and a cell per day, with the month label first", () => {
    const l = layoutField(fixture(), 1);
    expect(l.rows.map((r) => r.month)).toEqual(["2026-03", "2026-04", "2026-05"]);
    expect(l.rows[0].cells).toHaveLength(8 + 31);
    expect(l.rows[0].cells.slice(0, 7).map((c) => c.ch).join("")).toBe("2026-03");
    expect(l.rows[1].cells[8 + 30].ch).toBe(" ");
  });

  it("thins after 15 April 2026 in the fixture: lighter tones once the analyzed share falls", () => {
    const l = layoutField(fixture(), 1);
    const april = l.rows[1].cells.slice(8);
    expect(april[0].tone).toBe(5);
    expect(april[20].tone).toBe(2);
  });

  it("maps counts onto the ramp from blank to densest", () => {
    expect(levelFor(0, 100)).toBe(0);
    expect(RAMP[levelFor(1, 100)]).toBe(".");
    expect(RAMP[levelFor(100, 100)]).toBe("@");
    expect(levelFor(1000, 100)).toBe(RAMP.length - 1);
    expect(scaleMaxOf([{ date: "2026-01-01", published: 0, analyzed_30d: null }])).toBe(1);
    expect(toneFor(null)).toBe(1);
    expect(toneFor(0.9)).toBe(5);
  });

  it("refuses a file that is not the field shape, so no count is drawn from it", () => {
    expect(parseFieldData(null)).toBeNull();
    expect(parseFieldData({ source: "x", as_of: "x", from: "x", days: [] })).toBeNull();
    expect(parseFieldData({ source: "x", as_of: "x", from: "x", days: [{ date: "2026-1-1", published: 3, analyzed_30d: null }] })).toBeNull();
    expect(parseFieldData({ source: "x", as_of: "x", from: "x", days: [{ date: "2026-01-01", published: -1, analyzed_30d: null }] })).toBeNull();
    expect(parseFieldData({ source: "x", as_of: "x", from: "x", days: [{ date: "2026-01-01", published: 3, analyzed_30d: 1.2 }] })).toBeNull();
    expect(parseFieldData(fixture())).not.toBeNull();
  });
});
