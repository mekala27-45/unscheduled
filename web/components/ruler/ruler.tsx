import type { CSSProperties } from "react";
import type { TimelineEvent } from "@/lib/api/client";
import { formatDate, formatDateTime } from "@/lib/format";
import { describeRuler, layoutRuler, type RulerLayout } from "@/lib/ruler";

const WAIT_STEP = 32;
const LANE = 44;

type Vars = CSSProperties & Record<`--${string}`, string | number>;

/**
 * THE SIGNATURE. One hairline in real time from the first event to now; a notched tick for each
 * event, coloured by who published it; the waits as dimension lines with their days. The figure is
 * one image to assistive technology, described in a sentence, and the ordered list under it carries
 * every event with its date and source.
 */
export function Ruler({ id, events, now, layout: given }: { id: string; events: TimelineEvent[]; now: string; layout?: RulerLayout }) {
  const layout = given ?? layoutRuler(events, now);
  const lineY = Math.max(56, layout.waits.length * WAIT_STEP + 24);
  const height = lineY + 40 + layout.lanes * LANE + 8;
  const nvd = layout.waits.find((w) => w.key === "nvd");

  return (
    <figure className="ruler" aria-labelledby={`${id}-ruler-caption`}>
      {nvd ? (
        <div className="ruler__head">
          <span className="ruler__now num">{nvd.days === 1 ? "1 day" : `${nvd.days} days`}</span>
          <span className="ruler__now-label">
            {nvd.open ? `without NVD analysis, and counting. The NVD's latest status: ${layout.nvd.latest ?? "none yet"}.` : "from publication to NVD analysis."}
          </span>
        </div>
      ) : null}
      <div className="ruler__track" role="img" aria-label={describeRuler(id, layout)} style={{ "--line-y": `${lineY}px`, "--h": `${height}px` } as Vars}>
        {layout.waits.map((w, i) => (
          <div
            key={w.key}
            className="ruler__wait"
            data-open={w.open}
            style={{ "--x0": w.x0, "--x1": w.x1, "--wait-y": `${i * WAIT_STEP}px`, "--wait": w.key === "nvd" ? "var(--color-ink-2)" : w.key === "kev" ? "var(--chart-truth)" : "var(--chart-7)" } as Vars}
          >
            <span className="ruler__wait-end" style={{ left: 0 }} />
            {w.open ? null : <span className="ruler__wait-end" style={{ right: 0 }} />}
            <span className="ruler__wait-text">
              <strong>{w.label}</strong>, {w.span}
            </span>
          </div>
        ))}
        <div className="ruler__line" />
        <div className="ruler__axis" aria-hidden="true">
          {layout.axis.map((m) => (
            <span key={m.label} style={{ left: `${m.x * 100}%` }}>
              {m.label}
            </span>
          ))}
        </div>
        {layout.ticks.map((t) => (
          <span key={`tick-${t.n}`} className="ruler__tick" data-kind={t.kind} style={{ "--x": t.x } as Vars} />
        ))}
        {layout.ticks.map((t) => (
          <span key={`drop-${t.n}`} className="ruler__drop" style={{ "--x": t.x, "--lane-i": t.lane } as Vars} />
        ))}
        {layout.ticks
          .filter((t) => t.left > t.x)
          .map((t) => (
            <span key={`lead-${t.n}`} className="ruler__lead" style={{ "--x0": t.x, "--x1": t.left, "--lane-i": t.lane } as Vars} />
          ))}
        {layout.ticks.map((t) => (
          <div key={`label-${t.n}`} className="ruler__label" data-kind={t.kind} style={{ "--l": t.left, "--lane-i": t.lane } as Vars}>
            <b>
              <i className="ruler__swatch" />
              {t.title}
            </b>
            <span>{formatDate(t.at)}</span>
          </div>
        ))}
      </div>
      <ol className="ruler__events">
        {layout.ticks.map((t) => (
          <li key={`ev-${t.n}`} data-kind={t.kind}>
            <span className="ruler__marker">{t.n}</span>
            <time dateTime={t.at}>{formatDateTime(t.at)}</time>
            <span>
              <i className="ruler__swatch" aria-hidden="true" />
              {t.title}
              {t.value ? <span className="mono"> {t.value}</span> : null}
              <span className="src">from {t.source}</span>
            </span>
          </li>
        ))}
      </ol>
      <figcaption id={`${id}-ruler-caption`} className="chart-source">
        {id}, every dated event from {formatDate(layout.start, "long")} to {formatDate(layout.end, "long")}, in real time on one line.
      </figcaption>
    </figure>
  );
}
