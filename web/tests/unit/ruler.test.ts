import { describe, expect, it } from "vitest";
import { TIMELINE_FIXTURE } from "@/lib/fixtures/cve";
import { layoutRuler } from "@/lib/ruler";

// FIXTURE: the timeline is invented in the API's shape (lib/fixtures/api.ts) and adapted as the console adapts it; it is not a real CVE.
const { events, now } = TIMELINE_FIXTURE;

describe("the ruler on the fixture timeline", () => {
  const layout = layoutRuler(events, now);

  it("draws one tick per event, in time order, inside the line", () => {
    expect(layout.ticks).toHaveLength(events.length);
    const xs = layout.ticks.map((t) => t.x);
    expect([...xs].sort((a, b) => a - b)).toEqual(xs);
    for (const x of xs) {
      expect(x).toBeGreaterThanOrEqual(0);
      expect(x).toBeLessThanOrEqual(1);
    }
    expect(layout.ticks[0].kind).toBe("published");
    expect(layout.ticks[0].x).toBe(0);
  });

  it("keeps real time: the gap between ticks is proportional to the time between events", () => {
    const span = Date.parse(layout.end) - Date.parse(layout.start);
    for (const t of layout.ticks) {
      expect(t.x).toBeCloseTo((Date.parse(t.at) - Date.parse(layout.start)) / span, 6);
    }
  });

  it("draws the NVD wait as open, in days and counting, labelled with the last status as the NVD wrote it", () => {
    const nvd = layout.waits.find((w) => w.key === "nvd");
    expect(nvd).toBeDefined();
    expect(nvd?.open).toBe(true);
    expect(nvd?.label).toBe("NVD, Awaiting Analysis");
    // 2 March 2026 14:05 to 7 November 2026 12:00, whole days
    expect(nvd?.days).toBe(249);
    expect(nvd?.span).toBe("249 days and counting");
    expect(layout.nvd).toEqual({ analyzed: false, days: 249, latest: "Awaiting Analysis" });
  });

  it("closes the KEV and exploit waits at their events", () => {
    const kev = layout.waits.find((w) => w.key === "kev");
    const exploit = layout.waits.find((w) => w.key === "exploit");
    expect(kev).toMatchObject({ open: false, days: 119, span: "after 119 days" });
    expect(exploit).toMatchObject({ open: false, days: 78, span: "after 78 days" });
  });

  it("closes the NVD wait when a status the API marks analyzed arrives", () => {
    const analyzed = [...events, { at: "2026-08-01T00:00:00Z", kind: "nvd_status" as const, source: "nvd@nist.gov", value: "Analyzed", analyzed: true }];
    const l = layoutRuler(analyzed, now);
    const nvd = l.waits.find((w) => w.key === "nvd");
    expect(nvd).toMatchObject({ open: false, days: 151, label: "NVD analysis" });
    expect(l.ticks.find((t) => t.kind === "nvd_analyzed")?.title).toBe("NVD: Analyzed");
  });

  it("puts labels in lanes so two labels never overlap, moving a label along its lane before it would", () => {
    const width = 0.17;
    const byLane = new Map<number, [number, number][]>();
    for (const t of layout.ticks) {
      const box: [number, number] = [t.left, t.left + width];
      expect(box[1]).toBeLessThanOrEqual(1);
      const lane = byLane.get(t.lane) ?? [];
      for (const [a, b] of lane) expect(box[0] >= b || box[1] <= a).toBe(true);
      lane.push(box);
      byLane.set(t.lane, lane);
    }
    expect(layout.lanes).toBeLessThanOrEqual(4);
    // the first four labels take the four lanes, so the next one is led out along the lane that frees first
    expect(layout.ticks.some((t) => t.left > t.x)).toBe(true);
  });

  it("gives the same layout for the same input", () => {
    expect(layoutRuler(events, now)).toEqual(layoutRuler([...events].reverse(), now));
  });
});

describe("the prediction tick", () => {
  it("sits at publication, after the published tick, with the title it brings", () => {
    const published = events.find((e) => e.kind === "published");
    expect(published).toBeDefined();
    const prediction = {
      at: published!.at,
      kind: "prediction" as const,
      source: "unscheduled-band version 3, a prediction and not an NVD value",
      value: "62%, set HIGH or CRITICAL",
      analyzed: null,
      title: "Predicted CRITICAL",
    };
    const layout = layoutRuler([...events, prediction], now);
    const ticks = layout.ticks.filter((t) => t.x === 0);
    expect(ticks.map((t) => t.kind).slice(0, 2)).toEqual(["published", "prediction"]);
    const tick = layout.ticks.find((t) => t.kind === "prediction");
    expect(tick?.title).toBe("Predicted CRITICAL");
    expect(tick?.value).toBe("62%, set HIGH or CRITICAL");
  });
});
