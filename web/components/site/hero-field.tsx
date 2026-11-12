import type { CSSProperties } from "react";
import type { Loaded } from "@/lib/build-data";
import type { FieldData } from "@/lib/field";
import { formatDate } from "@/lib/format";
import { FieldCanvas } from "./field-canvas";

const CELL_H = 16;

/** A dot on every 8 by 16 cell: what the field shows without script, and while no data is loaded. */
function DotGrid() {
  return (
    <svg className="dotgrid" aria-hidden="true" focusable="false">
      <defs>
        <pattern id="field-dots" width="8" height="16" patternUnits="userSpaceOnUse">
          <circle cx="4" cy="8" r="1" />
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill="url(#field-dots)" />
    </svg>
  );
}

/**
 * The character field of the CVE stream, the hero's signature. It draws only from
 * web/public/data/field.json; with no file it is a dot grid and says so, and it never draws a count
 * that file does not hold.
 */
export function HeroField({ field }: { field: Loaded<FieldData> }) {
  const months = field.state === "ok" ? new Set(field.value.days.map((d) => d.date.slice(0, 7))).size : 0;
  const style = months ? ({ "--field-h": `${months * CELL_H + CELL_H}px`, "--field-h-narrow": `${months * CELL_H + CELL_H}px` } as CSSProperties) : undefined;
  return (
    <figure className="hero-field" style={style}>
      <div className="hero-field__frame">
        <DotGrid />
        {field.state === "ok" ? <FieldCanvas data={field.value} readoutId="field-readout" /> : null}
      </div>
      <figcaption className="hero-field__legend">
        {field.state === "ok" ? (
          <>
            <strong>One character a day</strong> of new CVEs since {formatDate(field.value.from, "long")}, denser for more CVEs, deeper blue
            for a larger share the NVD analyzed within 30 days. {field.value.source}, as of {formatDate(field.value.as_of, "long")}.
            <span id="field-readout" className="block text-fg-2" aria-live="off" />
          </>
        ) : field.state === "unreadable" ? (
          <>
            <strong>{field.file} could not be read</strong>, so the field is a dot grid. Nothing is drawn from a file this page cannot check.
          </>
        ) : (
          <>
            <strong>No data release yet:</strong> one dot per day of new CVEs since 1 January 2024.
          </>
        )}
      </figcaption>
    </figure>
  );
}
