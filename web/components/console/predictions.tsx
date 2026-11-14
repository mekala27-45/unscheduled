import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { Prediction, Predictions } from "@/lib/api/client";
import { formatDate, formatShare } from "@/lib/format";
import { EmptyState } from "./region";

const BANDS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
const METRIC_NAMES: Record<string, string> = {
  metric_AV: "Attack vector",
  metric_AC: "Attack complexity",
  metric_PR: "Privileges required",
  metric_UI: "User interaction",
  metric_S: "Scope",
  metric_C: "Confidentiality",
  metric_I: "Integrity",
  metric_A: "Availability",
};
const WINDOW_NAMES: Record<string, string> = {
  development: "the development window, which chose the models",
  test: "the test window, which judged them once",
  shadow: "the shadow window, where most CVEs have no NVD analysis",
};

/** The registered model and version that made a value, as every predicted value is labeled. */
export function madeBy(p: Prediction): string {
  return `${p.model}${p.version != null ? ` version ${p.version}` : ""}${p.role ? `, the ${p.role}` : ""}`;
}

function setWords(set: string[] | null): string {
  if (!set || set.length === 0) return "not given";
  return set.length === 1 ? `${set[0]} alone` : `${set.slice(0, -1).join(", ")} or ${set[set.length - 1]}`;
}

function BandBar({ p }: { p: Prediction }) {
  const probs = p.probabilities ?? {};
  return (
    <figure className="pbar">
      <div className="pbar__track" role="img" aria-label={`Band probabilities: ${BANDS.map((b) => `${b} ${formatShare(probs[b] ?? 0)}`).join(", ")}`}>
        {BANDS.map((b, i) => (
          <span
            key={b}
            className="pbar__seg"
            data-in-set={p.set?.includes(b) ? "true" : "false"}
            style={{ flexGrow: Math.max(probs[b] ?? 0, 0.0001), background: `var(--seq-${i + 2})` }}
            title={`${b} ${formatShare(probs[b] ?? 0, 1)}`}
          />
        ))}
      </div>
      <ul className="pbar__keys">
        {BANDS.map((b) => (
          <li key={b} data-in-set={p.set?.includes(b) ? "true" : "false"}>
            <span>{b}</span> <span className="num">{formatShare(probs[b] ?? 0)}</span>
          </li>
        ))}
      </ul>
    </figure>
  );
}

/** The chance of a KEV listing by day 30, 90 and 180, drawn as the steps of a survival curve. */
function ListingCurve({ p }: { p: Prediction }) {
  const by = (p.value && typeof p.value === "object" && !Array.isArray(p.value) ? p.value : {}) as Record<string, number>;
  const days = [30, 90, 180].filter((d) => by[String(d)] != null);
  if (days.length === 0) return null;
  const top = Math.max(...days.map((d) => by[String(d)]), 0.0001);
  const w = 280;
  const h = 92;
  const x = (d: number) => (d / 180) * (w - 8) + 4;
  const y = (v: number) => h - 22 - (v / top) * (h - 40);
  let path = `M ${x(0)} ${y(0)}`;
  let last = 0;
  for (const d of days) {
    path += ` H ${x(d)} V ${y(by[String(d)])}`;
    last = d;
  }
  return (
    <figure className="curve">
      <svg className="chart" viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`Chance of a KEV listing: ${days.map((d) => `${formatShare(by[String(d)], 2)} by day ${d}`).join(", ")}`}>
        <g className="grid">
          <line x1={x(0)} x2={x(180)} y1={y(0)} y2={y(0)} />
        </g>
        <path d={path} className="curve__line" />
        {days.map((d) => (
          <g key={d}>
            <circle cx={x(d)} cy={y(by[String(d)])} r={2.5} className="curve__dot" />
            <text x={x(d)} y={y(by[String(d)]) - 6} textAnchor={d === last ? "end" : "middle"}>
              {formatShare(by[String(d)], 2)}
            </text>
            <text x={x(d)} y={h} textAnchor={d === last ? "end" : "middle"}>
              day {d}
            </text>
          </g>
        ))}
      </svg>
    </figure>
  );
}

export function PredictionsView({ predictions, note, published }: { predictions: Predictions | null; note: string | null; published: string | null }) {
  if (!predictions) {
    return (
      <EmptyState
        title="No prediction for this CVE"
        body={note ? `${note[0].toUpperCase()}${note.slice(1)}.` : "The loaded data carries no prediction for it."}
        action={{ label: "How the models were chosen and judged", href: "/app/models" }}
      />
    );
  }
  const by = new Map(predictions.values.map((v) => [v.field, v]));
  const band = by.get("band");
  const cwe = by.get("cwe");
  const exploit = by.get("exploitation");
  const listing = by.get("kev_listing");
  const products = by.get("products");
  const metrics = predictions.values.filter((v) => v.field.startsWith("metric_"));
  const epss = (exploit?.detail?.epss ?? null) as { score?: number | null; percentile?: number | null; date?: string | null; note?: string } | null;
  return (
    <div className="predictions">
      <p className="text-app-sm text-fg-muted">
        {predictions.note} Batch {predictions.batch}
        {predictions.made_on ? `, made ${formatDate(predictions.made_on, "long")}` : ""}
        {predictions.window ? `, for a CVE published in ${WINDOW_NAMES[predictions.window] ?? predictions.window}` : ""}
        {published ? `, scored as known at the end of ${formatDate(published, "long")}` : ""}.
      </p>
      {band ? (
        <section className="prediction" aria-labelledby="pred-band">
          <h3 id="pred-band">Severity band</h3>
          <p className="prediction__value">
            <span className="prediction__word">{String(band.value)}</span>
            <span className="num">{formatShare(band.probability)}</span>
            <span className="text-fg-muted">likely; the 90 percent set is {setWords(band.set)}</span>
          </p>
          <BandBar p={band} />
          <p className="prediction__by">Prediction of {madeBy(band)}</p>
        </section>
      ) : null}
      {metrics.length ? (
        <section className="prediction" aria-labelledby="pred-metrics">
          <h3 id="pred-metrics">Base metrics</h3>
          <Table label="Predicted CVSS 3.1 base metrics">
            <TableHeader>
              <TableRow>
                <TableHead>Metric</TableHead>
                <TableHead>Predicted</TableHead>
                <TableHead className="num">Probability</TableHead>
                <TableHead>90 percent set</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {metrics.map((m) => (
                <TableRow key={m.field}>
                  <TableCell className="lead">{METRIC_NAMES[m.field] ?? m.field}</TableCell>
                  <TableCell className="mono">{String(m.value)}</TableCell>
                  <TableCell className="num">{formatShare(m.probability)}</TableCell>
                  <TableCell className="mono">{(m.set ?? []).join(" or ")}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <p className="prediction__by">Prediction of {madeBy(metrics[0])}</p>
        </section>
      ) : null}
      {cwe ? (
        <section className="prediction" aria-labelledby="pred-cwe">
          <h3 id="pred-cwe">Weakness</h3>
          <p className="prediction__value">
            <span className="prediction__word mono">{String(cwe.value)}</span>
            <span className="num">{formatShare(cwe.probability)}</span>
            <span className="text-fg-muted">likely</span>
          </p>
          <p className="text-app-sm">
            The five most likely: <span className="mono">{((cwe.detail?.top5 as string[] | undefined) ?? []).join(", ")}</span>
          </p>
          <p className="prediction__by">Prediction of {madeBy(cwe)}</p>
        </section>
      ) : null}
      {exploit ? (
        <section className="prediction" aria-labelledby="pred-exploit">
          <h3 id="pred-exploit">Exploitation</h3>
          <p className="prediction__value">
            <span className="prediction__word num">{formatShare(exploit.probability, 2)}</span>
            <span className="text-fg-muted">chance of a KEV listing within 180 days, scored at publication</span>
          </p>
          <p className="text-app-sm">
            Higher than <span className="num">{Number(exploit.detail?.percentile ?? 0).toFixed(1)}</span> percent of the CVEs in the batch.
            EPSS beside it:{" "}
            {epss?.score != null ? (
              <>
                <span className="num">{epss.score.toFixed(5)}</span>
                {epss.date ? <span className="text-fg-muted"> on {formatDate(epss.date)}</span> : null}
              </>
            ) : (
              <span className="text-fg-muted">no score held</span>
            )}
            .
          </p>
          {epss?.note ? <p className="text-app-xs text-fg-muted">{epss.note}</p> : null}
          {listing ? <ListingCurve p={listing} /> : null}
          <p className="prediction__by">
            Prediction of {madeBy(exploit)}
            {listing ? `; the curve of ${madeBy(listing)}` : ""}
          </p>
        </section>
      ) : null}
      {products ? (
        <section className="prediction" aria-labelledby="pred-products">
          <h3 id="pred-products">Affected products</h3>
          {Array.isArray(products.value) && products.value.length ? (
            <ol className="prediction__list mono">
              {products.value.map((v) => (
                <li key={v}>{v}</li>
              ))}
            </ol>
          ) : (
            <p className="text-app-sm text-fg-muted">No candidate in the CPE dictionary.</p>
          )}
          <p className="prediction__by">Candidates to check, not a match. Prediction of {madeBy(products)}</p>
        </section>
      ) : null}
    </div>
  );
}
