/**
 * The ruler's geometry: one line in real time from the first event to now, a notched tick per event,
 * and the waits as dimension lines. Pure, so the layout is tested on a fixture without a browser.
 * The NVD status words are drawn as the API returns them; whether a status counts as analyzed is the
 * API's call (config/labels.yaml), carried on each event as `analyzed`.
 */
import type { TimelineEvent } from "./api/client";
import { DAY, formatDate, parseDate } from "./format";

export type TickKind = TimelineEvent["kind"] | "nvd_analyzed";

export type RulerTick = {
  n: number;
  /** Where the event is on the line, in real time, 0 to 1. */
  x: number;
  /** Where its label starts in its lane, 0 to 1; a leader joins it to the tick when the two differ. */
  left: number;
  at: string;
  kind: TickKind;
  title: string;
  value: string | null;
  source: string;
  lane: number;
};

export type RulerWait = {
  key: "nvd" | "kev" | "exploit";
  x0: number;
  x1: number;
  days: number;
  open: boolean;
  label: string;
  span: string;
};

export type RulerAxisMark = { x: number; label: string };

export type RulerLayout = {
  start: string;
  end: string;
  ticks: RulerTick[];
  waits: RulerWait[];
  axis: RulerAxisMark[];
  lanes: number;
  nvd: { analyzed: boolean; days: number; latest: string | null };
};

const ORDER: Record<TimelineEvent["kind"], number> = {
  published: 0, prediction: 1, filer_score: 2, ghsa_advisory: 3, nvd_status: 4, cisa_adp: 5, exploit_code: 6, kev_listed: 7, rejected: 8,
};

export function titleOf(e: TimelineEvent): string {
  switch (e.kind) {
    case "published": return "Published";
    case "filer_score": return "Filer score";
    case "nvd_status": return e.value ? `NVD: ${e.value}` : "NVD status";
    case "cisa_adp": return "CISA ADP";
    case "kev_listed": return "KEV listing";
    case "exploit_code": return "Exploit code";
    case "ghsa_advisory": return "GitHub advisory";
    case "rejected": return "Rejected";
    case "prediction": return e.title ?? "Prediction";
  }
}

function days(a: number, b: number): number {
  return Math.floor(Math.abs(b - a) / DAY);
}

function plural(n: number): string {
  return `${n} ${n === 1 ? "day" : "days"}`;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function axisMarks(t0: number, t1: number): RulerAxisMark[] {
  const span = t1 - t0;
  const first = new Date(t0);
  const candidates: number[] = [];
  let y = first.getUTCFullYear();
  let m = first.getUTCMonth() + 1;
  for (let guard = 0; guard < 600; guard++) {
    if (m > 11) { m = 0; y += 1; }
    const t = Date.UTC(y, m, 1);
    if (t > t1) break;
    candidates.push(t);
    m += 1;
  }
  const steps = [1, 2, 3, 6, 12, 24];
  const step = steps.find((s) => Math.ceil(candidates.length / s) <= 7) ?? 24;
  const yearly = step >= 12;
  return candidates
    .filter((t) => {
      const d = new Date(t);
      return yearly ? d.getUTCMonth() === 0 && (d.getUTCFullYear() % (step / 12) === 0) : (d.getUTCFullYear() * 12 + d.getUTCMonth()) % step === 0;
    })
    .map((t) => {
      const d = new Date(t);
      return { x: (t - t0) / span, label: yearly ? String(d.getUTCFullYear()) : `${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}` };
    })
    .filter((mark) => mark.x > 0.03 && mark.x < 0.97);
}

/**
 * labelWidth is the share of the track one label takes (about 22 characters). A label starts at its
 * tick in the first lane that is free there; when every lane is taken it moves right along the lane
 * that frees first, and a leader joins it back to its tick. The tick itself never moves: the line
 * stays in real time.
 */
export function layoutRuler(events: TimelineEvent[], now: string, labelWidth = 0.17, maxLanes = 4): RulerLayout {
  const valid = events
    .map((e, i) => ({ e, i, t: parseDate(e.at)?.getTime() ?? NaN }))
    .filter((x) => Number.isFinite(x.t))
    .sort((a, b) => a.t - b.t || ORDER[a.e.kind] - ORDER[b.e.kind] || a.i - b.i);
  const nowT = parseDate(now)?.getTime() ?? Date.now();
  const published = valid.find((x) => x.e.kind === "published");
  const t0 = valid.length ? valid[0].t : nowT - DAY;
  const t1 = Math.max(nowT, valid.length ? valid[valid.length - 1].t : nowT, t0 + DAY);
  const span = t1 - t0;
  const xOf = (t: number) => Math.min(1, Math.max(0, (t - t0) / span));
  const gap = 0.01;
  const maxLeft = 1 - labelWidth;

  const laneEnds: number[] = [];
  const ticks: RulerTick[] = valid.map(({ e, t }, k) => {
    const x = xOf(t);
    const want = Math.min(x, maxLeft);
    let lane = laneEnds.findIndex((end) => end <= want);
    let left = want;
    if (lane === -1 && laneEnds.length < maxLanes) {
      lane = laneEnds.length;
      laneEnds.push(0);
    } else if (lane === -1) {
      lane = laneEnds.indexOf(Math.min(...laneEnds));
      left = Math.min(maxLeft, Math.max(want, laneEnds[lane]));
    }
    laneEnds[lane] = left + labelWidth + gap;
    return {
      n: k + 1,
      x,
      left,
      at: e.at,
      kind: e.kind === "nvd_status" && e.analyzed ? "nvd_analyzed" : e.kind,
      title: titleOf(e),
      value: e.kind === "nvd_status" ? null : e.value,
      source: e.source,
      lane,
    };
  });

  const waits: RulerWait[] = [];
  const startT = published ? published.t : t0;
  const statuses = valid.filter((x) => x.e.kind === "nvd_status");
  const analyzedAt = statuses.find((x) => x.e.analyzed === true);
  const latest = statuses.length ? statuses[statuses.length - 1].e.value : null;
  if (published) {
    if (analyzedAt) {
      const n = days(startT, analyzedAt.t);
      waits.push({ key: "nvd", x0: xOf(startT), x1: xOf(analyzedAt.t), days: n, open: false, label: "NVD analysis", span: `after ${plural(n)}` });
    } else {
      const n = days(startT, nowT);
      waits.push({ key: "nvd", x0: xOf(startT), x1: xOf(nowT), days: n, open: true, label: latest ? `NVD, ${latest}` : "NVD, no status yet", span: `${plural(n)} and counting` });
    }
    const kev = valid.find((x) => x.e.kind === "kev_listed");
    if (kev) {
      const n = days(startT, kev.t);
      waits.push({ key: "kev", x0: xOf(Math.min(startT, kev.t)), x1: xOf(Math.max(startT, kev.t)), days: n, open: false, label: "KEV listing", span: kev.t >= startT ? `after ${plural(n)}` : `${plural(n)} before publication` });
    }
    const exploit = valid.find((x) => x.e.kind === "exploit_code");
    if (exploit) {
      const n = days(startT, exploit.t);
      waits.push({ key: "exploit", x0: xOf(Math.min(startT, exploit.t)), x1: xOf(Math.max(startT, exploit.t)), days: n, open: false, label: "Exploit code", span: exploit.t >= startT ? `after ${plural(n)}` : `${plural(n)} before publication` });
    }
  }

  return {
    start: new Date(t0).toISOString(),
    end: new Date(t1).toISOString(),
    ticks,
    waits,
    axis: axisMarks(t0, t1),
    lanes: Math.max(1, laneEnds.length),
    nvd: {
      analyzed: Boolean(analyzedAt),
      days: published ? days(startT, analyzedAt ? analyzedAt.t : nowT) : 0,
      latest,
    },
  };
}

export function describeRuler(id: string, layout: RulerLayout): string {
  const first = layout.ticks[0];
  const parts = [`Timeline of ${id} from ${formatDate(layout.start, "long")} to ${formatDate(layout.end, "long")}`, `${layout.ticks.length} events`];
  if (first) parts.push(`first: ${first.title}`);
  const nvd = layout.waits.find((w) => w.key === "nvd");
  if (nvd) parts.push(`${nvd.label}, ${nvd.span}`);
  return parts.join("; ") + ".";
}
