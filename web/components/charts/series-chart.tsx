"use client";

import { useEffect, useRef, useState } from "react";
import type { BacklogQuestion } from "@/lib/api/client";

const DASHES = ["", "7 4", "2 3", "10 3 2 3", "4 2", "1 2", "12 4", "6 2 2 2"];

function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(720);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => setWidth(Math.max(280, Math.round(entry.contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, width];
}

function niceMax(max: number): number {
  if (max <= 0) return 1;
  const step = 10 ** Math.floor(Math.log10(max));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * step >= max) return m * step;
  return 10 * step;
}

function fmt(n: number, unit: string): string {
  if (unit === "share") return `${Math.round(n * 100)}%`;
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: n < 10 ? 1 : 0 }).format(n);
}

const slotVar = (slot: number) => `var(--chart-${Math.min(8, Math.max(1, slot))})`;

/** A line over time on one y-axis from zero: hairline grid, 2px lines, a dash per series as well as a hue. */
export function LineChart({ q }: { q: BacklogQuestion }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const height = 260;
  const pad = { top: 16, right: 16, bottom: 28, left: 48 };
  const w = width - pad.left - pad.right;
  const h = height - pad.top - pad.bottom;
  const values = q.series.flatMap((s) => s.values.filter((v): v is number => v != null));
  const max = niceMax(Math.max(0, ...values));
  const x = (i: number) => pad.left + (q.x.length <= 1 ? w / 2 : (i / (q.x.length - 1)) * w);
  const y = (v: number) => pad.top + h - (v / max) * h;
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * max);
  const labelEvery = Math.max(1, Math.ceil(q.x.length / Math.max(2, Math.floor(w / 90))));
  const ruleIndex = q.rule ? q.x.indexOf(q.rule.x) : -1;
  const [hover, setHover] = useState<number | null>(null);

  return (
    <div ref={ref}>
      <svg
        className="chart"
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label={`${q.title}. ${q.series.map((s) => s.label).join(", ")}, ${q.x[0]} to ${q.x[q.x.length - 1]}. The table toggle shows every value.`}
        onPointerMove={(e) => {
          const box = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
          const i = Math.round(((e.clientX - box.left - pad.left) / w) * (q.x.length - 1));
          setHover(i >= 0 && i < q.x.length ? i : null);
        }}
        onPointerLeave={() => setHover(null)}
      >
        <g className="grid">
          {ticks.map((t) => (
            <line key={t} x1={pad.left} x2={width - pad.right} y1={y(t)} y2={y(t)} />
          ))}
        </g>
        {ticks.map((t) => (
          <text key={`l${t}`} x={pad.left - 8} y={y(t) + 4} textAnchor="end">
            {fmt(t, q.unit)}
          </text>
        ))}
        {q.x.map((label, i) =>
          i % labelEvery === 0 ? (
            <text key={label} x={x(i)} y={height - 8} textAnchor="middle">
              {label}
            </text>
          ) : null,
        )}
        {ruleIndex >= 0 && q.rule ? (
          <g>
            <line className="rule-mark" x1={x(ruleIndex)} x2={x(ruleIndex)} y1={pad.top} y2={pad.top + h} />
            <text className="rule-mark-label" x={x(ruleIndex) + 6} y={pad.top + 12}>
              {q.rule.label}
            </text>
          </g>
        ) : null}
        {q.series.map((s, k) => {
          let d = "";
          s.values.forEach((v, i) => {
            if (v == null) return;
            d += `${d && s.values[i - 1] != null ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`;
          });
          return <path key={s.key} className="series" d={d} stroke={slotVar(s.slot)} strokeDasharray={DASHES[k % DASHES.length] || undefined} />;
        })}
        {hover != null ? <line className="rule-mark" x1={x(hover)} x2={x(hover)} y1={pad.top} y2={pad.top + h} strokeDasharray="2 3" /> : null}
      </svg>
      <div className="chart-legend">
        {q.series.map((s, k) => (
          <span key={s.key}>
            <i style={{ ["--swatch" as string]: slotVar(s.slot) }} data-dash={k % DASHES.length > 0} />
            {s.label}
            {hover != null && s.values[hover] != null ? `: ${fmt(s.values[hover] as number, q.unit)} in ${q.x[hover]}` : ""}
          </span>
        ))}
      </div>
    </div>
  );
}

/** Horizontal bars from zero, the category in words on the left, the value in figures on the right. */
export function BarChart({ q }: { q: BacklogQuestion }) {
  const s = q.series[0];
  const values = s?.values ?? [];
  const max = niceMax(Math.max(0, ...values.filter((v): v is number => v != null)));
  return (
    <div className="grid gap-2xs" role="img" aria-label={`${q.title}. The table toggle shows every value.`}>
      {q.x.map((label, i) => {
        const v = values[i];
        return (
          <div key={label} className="grid grid-cols-[minmax(8rem,14rem)_minmax(0,1fr)_4.5rem] items-center gap-sm text-app-sm">
            <span className="truncate text-fg-2">{label}</span>
            <span className="h-[18px] bg-sunken">
              <span className="block h-full" style={{ width: v == null ? 0 : `${(v / max) * 100}%`, background: slotVar(s?.slot ?? 1) }} />
            </span>
            <span className="num text-right">{v == null ? "none" : fmt(v, q.unit)}</span>
          </div>
        );
      })}
    </div>
  );
}

export function SeriesTable({ q }: { q: BacklogQuestion }) {
  return (
    <div className="dtable-wrap" role="region" aria-label={`${q.title}, as a table`} tabIndex={0}>
      <table className="dtable">
        <caption>
          {q.source}, {q.window}
        </caption>
        <thead>
          <tr>
            <th scope="col">{q.kind === "line" ? "Period" : "Category"}</th>
            {q.series.map((s) => (
              <th key={s.key} scope="col" className="num">
                {s.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {q.x.map((label, i) => (
            <tr key={label}>
              <td className="lead">{label}</td>
              {q.series.map((s) => (
                <td key={s.key} className="num">
                  {s.values[i] == null ? "none" : fmt(s.values[i] as number, q.unit)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
