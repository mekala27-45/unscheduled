const MARKS: { label: string; kind: string; x: number; lane: 0 | 1 }[] = [
  { label: "Published", kind: "published", x: 30, lane: 0 },
  { label: "Filer score", kind: "filer_score", x: 112, lane: 1 },
  { label: "GitHub advisory", kind: "ghsa_advisory", x: 210, lane: 0 },
  { label: "CISA ADP", kind: "cisa_adp", x: 304, lane: 1 },
  { label: "NVD status", kind: "nvd_status", x: 390, lane: 0 },
  { label: "Exploit code", kind: "exploit_code", x: 476, lane: 1 },
  { label: "KEV listing", kind: "kev_listed", x: 560, lane: 0 },
];

const LINE_Y = 92;

/**
 * A key to the ruler, drawn in its own notation: the line, a notched tick per kind of event, and the
 * NVD wait as a dimension line. A key, not a timeline: no dates and no counts.
 */
export function RulerKey() {
  return (
    <figure className="rulerkey">
      <svg
        className="rulerkey__svg diagram"
        viewBox="0 0 640 200"
        role="img"
        aria-label="Key to the ruler's marks: published, filer score, GitHub advisory, CISA ADP, each NVD status, exploit code and KEV listing, with the NVD wait drawn as a dimension line"
      >
        <g className="rk-wait">
          <line x1="30" x2="540" y1="44" y2="44" strokeDasharray="4 4" />
          <line x1="30" x2="30" y1="37" y2="51" />
          <text x="38" y="32">NVD, no analysis, days and counting</text>
        </g>
        <line className="rk-line" x1="18" x2="622" y1={LINE_Y} y2={LINE_Y} />
        {MARKS.map((m) => {
          const ty = m.lane === 0 ? 136 : 174;
          return (
            <g key={m.kind} className={`rk-mark rk-${m.kind}`}>
              <polygon points={`${m.x - 4},${LINE_Y - 13} ${m.x + 4},${LINE_Y - 13} ${m.x},${LINE_Y - 8}`} />
              <line className="rk-tick" x1={m.x} x2={m.x} y1={LINE_Y - 8} y2={LINE_Y + 8} />
              <line className="rk-drop" x1={m.x} x2={m.x} y1={LINE_Y + 12} y2={ty - 14} />
              <text x={m.x + 6} y={ty}>
                {m.label}
              </text>
            </g>
          );
        })}
      </svg>
      <figcaption>A key, not a timeline.</figcaption>
    </figure>
  );
}
