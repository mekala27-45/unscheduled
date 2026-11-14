"use client";

import Link from "next/link";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useModels } from "@/lib/api/queries";
import { formatDate, formatShare } from "@/lib/format";
import { PageHead } from "./page-head";
import { EmptyState, ErrorState, Loading, Region, SkeletonLines, SkeletonTable } from "./region";
import { StatusText } from "./status-text";

type Rec = Record<string, unknown>;
const isRec = (v: unknown): v is Rec => typeof v === "object" && v !== null && !Array.isArray(v);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const fixed = (v: unknown, d = 3): string => (num(v) == null ? "not measured" : (num(v) as number).toFixed(d));
const interval = (e: unknown, d = 3): string => {
  if (!isRec(e)) return "not measured";
  return `${fixed(e.value, d)} (${fixed(e.low, d)} to ${fixed(e.high, d)})`;
};

const PURPOSE: Record<string, { forWhat: string; notFor: string }> = {
  "unscheduled-band": { forWhat: "a first severity band for a CVE the NVD has not analyzed", notFor: "replacing an NVD or filer score, or any decision that needs an official one" },
  "unscheduled-metrics": { forWhat: "the eight CVSS 3.1 base metrics behind the band", notFor: "a vector to file as a score" },
  "unscheduled-cwe": { forWhat: "the weakness class, among the 50 most frequent in train", notFor: "a rare CWE, which it calls other" },
  "unscheduled-exploit": { forWhat: "ranking CVEs by the chance of a KEV listing within 180 days, at publication", notFor: "a probability of exploitation, since KEV is a lower bound" },
  "unscheduled-survival": { forWhat: "when a listing tends to come, by day 30, 90 and 180", notFor: "a date for any one CVE" },
  "unscheduled-product": { forWhat: "a short list of CPE vendor and product pairs to check", notFor: "an affected configuration, which only the NVD's analysis gives" },
};

function Verdict({ verdict }: { verdict: unknown }) {
  if (verdict === "met") return <StatusText tone="good">Met</StatusText>;
  if (verdict === "not met") return <StatusText tone="serious">Not met</StatusText>;
  return <StatusText tone="quiet">Not scored yet</StatusText>;
}

const SCORED_ONCE =
  "Test is scored once, after the operating points are frozen and hashed; this region fills from the release that carries that scoring.";

function NotYet({ what, body = SCORED_ONCE }: { what: string; body?: string }) {
  return <EmptyState title={`Not in this release yet: ${what}`} body={body} action={{ label: "Read the criteria", href: "/app/criteria" }} />;
}

function ModelCards({ models }: { models: Rec[] }) {
  return (
    <div className="grid gap-lg">
      {models.map((m) => {
        const name = String(m.name);
        const versions = Array.isArray(m.versions) ? (m.versions as Rec[]) : [];
        const chosen = isRec(m.aliases) ? num(m.aliases.chosen) : null;
        const purpose = PURPOSE[name];
        return (
          <article key={name} className="card" aria-labelledby={`card-${name}`}>
            <h3 id={`card-${name}`} className="mono">
              {name}
            </h3>
            <p className="text-app-sm">{String(m.description ?? "")}</p>
            {purpose ? (
              <p className="text-app-sm text-fg-2">
                For {purpose.forWhat}. Not for {purpose.notFor}.
              </p>
            ) : null}
            <Table label={`The versions of ${name}`}>
              <TableHeader>
                <TableRow>
                  <TableHead>Version</TableHead>
                  <TableHead>What it is</TableHead>
                  <TableHead>Stage</TableHead>
                  <TableHead className="num">Development</TableHead>
                  <TableHead className="num">Test</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {versions.map((v) => {
                  const dev = isRec(v.dev) ? v.dev : {};
                  const test = isRec(v.test) ? v.test : {};
                  const first = (r: Rec) => Object.entries(r).filter(([, x]) => typeof x === "number").slice(0, 2);
                  return (
                    <TableRow key={String(v.version)}>
                      <TableCell className="lead num">
                        {String(v.version)}
                        {chosen === num(v.version) ? <span className="text-fg-muted"> chosen</span> : null}
                      </TableCell>
                      <TableCell>
                        {String(v.role)}: {String(v.description ?? v.run_name ?? "")}
                      </TableCell>
                      <TableCell>{String(v.stage)}</TableCell>
                      <TableCell className="num">
                        {first(dev).map(([k, x]) => `${k} ${fixed(x)}`).join(", ") || "none"}
                      </TableCell>
                      <TableCell className="num">
                        {first(test).map(([k, x]) => `${k} ${fixed(x)}`).join(", ") || "not scored"}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            <p className="prediction__by">Chosen by {String(m.chosen_by ?? "the operating points")}</p>
          </article>
        );
      })}
    </div>
  );
}

function C1View({ c1 }: { c1: Rec }) {
  const kappa = isRec(c1.kappa) ? c1.kappa : {};
  return (
    <dl className="facts">
      <dt>Verdict</dt>
      <dd>
        <Verdict verdict={c1.verdict} />
      </dd>
      <dt>Band kappa, the model</dt>
      <dd className="num">{interval(kappa.model)}</dd>
      <dt>Band kappa, the floor</dt>
      <dd className="num">{interval(kappa.floor)}</dd>
      <dt>Paired difference</dt>
      <dd className="num">{interval(kappa.difference)}</dd>
      <dt>Calibration error</dt>
      <dd className="num">{interval(c1.ece)}</dd>
      <dt>Population</dt>
      <dd>
        {String(c1.population ?? "")}, {String(isRec(kappa) ? (kappa.rows ?? "") : "")} CVEs in {String(isRec(kappa) ? (kappa.clusters ?? "") : "")} filer clusters
      </dd>
    </dl>
  );
}

function Reliability({ bins, label }: { bins: Rec[]; label: string }) {
  const w = 280;
  const h = 200;
  const x = (v: number) => 24 + v * (w - 32);
  const y = (v: number) => h - 20 - v * (h - 32);
  return (
    <figure className="reliability">
      <svg className="chart" viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`${label}: accuracy against confidence in ${bins.length} bins`}>
        <g className="grid">
          <line x1={x(0)} y1={y(0)} x2={x(1)} y2={y(1)} strokeDasharray="3 3" />
          <line x1={x(0)} y1={y(0)} x2={x(1)} y2={y(0)} />
        </g>
        {bins.map((b) => {
          const c = num(b.confidence) ?? 0;
          const a = num(b.accuracy) ?? 0;
          return <circle key={String(b.low)} cx={x(c)} cy={y(a)} r={Math.max(2, Math.min(7, Math.sqrt((num(b.rows) ?? 1) / 50)))} className="curve__dot" />;
        })}
        <text x={x(0)} y={h - 4}>0</text>
        <text x={x(1)} y={h - 4} textAnchor="end">
          confidence 1
        </text>
        <text x={4} y={y(1) + 4}>1</text>
      </svg>
      <figcaption className="chart-source">{label}. The dashed line is perfect calibration; each dot is a bin, sized by its CVEs.</figcaption>
    </figure>
  );
}

function C2View({ c2 }: { c2: Rec }) {
  const r = isRec(c2.recall_at_top5) ? c2.recall_at_top5 : {};
  const rows = ["model", "epss_day_1", "epss_day_7", "epss_day_30"].filter((k) => isRec(r[k]));
  const names: Record<string, string> = { model: "The model, at publication", epss_day_1: "EPSS on day 1", epss_day_7: "EPSS on day 7", epss_day_30: "EPSS on day 30" };
  return (
    <>
      <p className="mb-md">
        <Verdict verdict={c2.verdict} />{" "}
        <span className="text-app-sm text-fg-muted">
          Recall of KEV listings within 180 days in the top {String(r.top ?? "")} of {String(r.rows ?? "")} test CVEs ({String(r.positives ?? "")} listed).
        </span>
      </p>
      <Table label="Recall at the top 5 percent, with EPSS beside">
        <TableHeader>
          <TableRow>
            <TableHead>Ranked by</TableHead>
            <TableHead className="num">Recall with its interval</TableHead>
            <TableHead>Against the model</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((k) => {
            const diff = isRec(r[`model_minus_${k}`]) ? (r[`model_minus_${k}`] as Rec) : null;
            return (
              <TableRow key={k}>
                <TableCell className="lead">{names[k]}</TableCell>
                <TableCell className="num">{interval(r[k])}</TableCell>
                <TableCell>{diff ? `${String(diff.reading)}, difference ${interval(diff)}` : "the reference"}</TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
      <p className="mt-sm text-app-xs text-fg-muted">{String(c2.note ?? "")}. A difference whose interval holds zero is a tie.</p>
    </>
  );
}

function Coverage({ secondary }: { secondary: Rec }) {
  const conf = isRec(secondary.conformal) ? secondary.conformal : {};
  const heads = Object.entries(conf).filter(([, v]) => isRec(v));
  if (heads.length === 0) return <NotYet what="conformal coverage on test" />;
  return (
    <Table label="Conformal coverage and set size on test, target 90 percent">
      <TableHeader>
        <TableRow>
          <TableHead>Head</TableHead>
          <TableHead className="num">Coverage</TableHead>
          <TableHead className="num">Mean set size</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {heads.map(([head, v]) => {
          const e = v as Rec;
          const overall = isRec(e.overall) ? e.overall : e;
          return (
            <TableRow key={head}>
              <TableCell className="lead">{head}</TableCell>
              <TableCell className="num">{formatShare(num(overall.coverage), 1)}</TableCell>
              <TableCell className="num">{fixed(overall.mean_size, 2)}</TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

function Slices({ slices }: { slices: Rec }) {
  const families = Object.entries(isRec(slices.fill) ? slices.fill : {});
  if (families.length === 0) return <NotYet what="the slices" />;
  return (
    <div className="grid gap-lg">
      {families.map(([family, rows]) => (
        <Table key={family} label={`Band kappa of the model against the floor by ${family}, Benjamini-Hochberg at 0.05`}>
          <TableHeader>
            <TableRow>
              <TableHead>{family}</TableHead>
              <TableHead className="num">CVEs</TableHead>
              <TableHead className="num">Model</TableHead>
              <TableHead className="num">Floor</TableHead>
              <TableHead>Difference</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {(Array.isArray(rows) ? (rows as Rec[]) : []).slice(0, 25).map((r) => (
              <TableRow key={String(r.slice)}>
                <TableCell className="lead">{String(r.slice)}</TableCell>
                <TableCell className="num">{String(r.rows)}</TableCell>
                <TableCell className="num">{r.tested ? fixed(r.a) : "too few"}</TableCell>
                <TableCell className="num">{r.tested ? fixed(r.b) : ""}</TableCell>
                <TableCell>{r.tested ? `${fixed(r.difference)}${r.significant ? ", significant after correction" : ", not significant"}` : "not tested"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ))}
    </div>
  );
}

function Taxonomy({ taxonomy }: { taxonomy: Rec }) {
  const cats = Array.isArray(taxonomy.categories) ? (taxonomy.categories as Rec[]) : [];
  if (cats.length === 0) return <NotYet what="the failure taxonomy" body="The misses are drawn from development and read by hand; this region fills from the release that carries the taxonomy." />;
  return (
    <Table label="The failure taxonomy: 100 development band misses, read and coded">
      <TableHeader>
        <TableRow>
          <TableHead>Category</TableHead>
          <TableHead className="num">Misses</TableHead>
          <TableHead>What it means</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {cats.map((c) => (
          <TableRow key={String(c.name)}>
            <TableCell className="lead">{String(c.name)}</TableCell>
            <TableCell className="num">{String(c.count)}</TableCell>
            <TableCell>{String(c.meaning ?? "")}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function Reweighting({ w }: { w: Rec }) {
  return (
    <dl className="facts">
      <dt>Band kappa, plain</dt>
      <dd className="num">{fixed(w.plain_qwk)}</dd>
      <dt>Band kappa, weighted toward the skipped</dt>
      <dd className="num">{fixed(w.weighted_qwk)}</dd>
      <dt>Effective sample size</dt>
      <dd className="num">
        {fixed(w.kish_ess, 0)} of {String(w.rows ?? "")} analyzed shadow CVEs
      </dd>
      <dt>Weights clipped at</dt>
      <dd className="num">
        {String(w.clip ?? "")}, {String(w.clipped ?? 0)} weights clipped
      </dd>
    </dl>
  );
}

export function ModelsView() {
  const q = useModels();
  const doc = q.data?.document ?? null;
  const evidence = doc && isRec(doc.evidence) ? doc.evidence : {};
  const models = doc && Array.isArray(doc.models) ? (doc.models as Rec[]) : [];
  const region = (content: () => React.ReactNode, skeleton: React.ReactNode, what: string) =>
    q.isPending ? (
      <Loading label={what}>{skeleton}</Loading>
    ) : q.isError ? (
      <p className="text-app-sm text-fg-muted">Not drawn: the models request above failed.</p>
    ) : !doc ? (
      <EmptyState title="This release carries no models" body={q.data?.note ?? "The serving release has no models document."} action={{ label: "Open the data page", href: "/app/data" }} />
    ) : (
      content()
    );
  return (
    <>
      <PageHead
        title="Models"
        meta={
          q.data ? (
            <>
              <span>Data version {q.data.data_version}</span>
              {doc?.made_on ? <span>Batch made {formatDate(String(doc.made_on))}</span> : null}
            </>
          ) : undefined
        }
      >
        Every model with its floor, how each was chosen on development and judged once on test, with the intervals, the calibration, the sets, the
        slices and the misses read by hand. Every value is a prediction, never an NVD value.
      </PageHead>
      {q.isError ? <ErrorState error={q.error} what="The models" onRetry={() => void q.refetch()} /> : null}
      <Region id="cards" title="The model cards" note="What each model is for and not for, its versions and their scores">
        {region(() => (models.length ? <ModelCards models={models} /> : <NotYet what="the model cards" body="The cards fill from the registry export the serving release carries." />), <SkeletonTable rows={6} cols={5} />, "The model cards")}
      </Region>
      <Region id="c1" title="C1, the fill" note="Band kappa on test CVEs with an NVD band, paired with the floor by filer, and the calibration error">
        {region(() => (isRec(evidence.c1) ? <C1View c1={evidence.c1} /> : <NotYet what="C1" />), <SkeletonLines lines={6} />, "C1")}
      </Region>
      <Region id="reliability" title="Reliability" note="Test, after the temperature frozen on development">
        {region(
          () =>
            isRec(evidence.c1) && Array.isArray(evidence.c1.reliability) ? (
              <Reliability bins={evidence.c1.reliability as Rec[]} label="The band on test" />
            ) : (
              <NotYet what="the reliability curve on test" />
            ),
          <SkeletonLines lines={6} />,
          "Reliability",
        )}
      </Region>
      <Region id="c2" title="C2, the rank, with EPSS beside" note="Recall of KEV within 180 days in the top 5 percent of test CVEs, scored at publication">
        {region(() => (isRec(evidence.c2) ? <C2View c2={evidence.c2} /> : <NotYet what="C2" />), <SkeletonTable rows={4} cols={3} />, "C2")}
      </Region>
      <Region id="conformal" title="Conformal coverage" note="The 90 percent sets fit on development, measured on test">
        {region(() => (isRec(evidence.secondary) ? <Coverage secondary={evidence.secondary} /> : <NotYet what="conformal coverage on test" />), <SkeletonTable rows={4} cols={3} />, "Coverage")}
      </Region>
      <Region id="reweighting" title="The CVEs the NVD skipped" note="Plain beside weighted, never one without the other">
        {region(() => (isRec(evidence.reweighting) ? <Reweighting w={evidence.reweighting} /> : <NotYet what="the reweighted view" body="The weights are fit with the operating points on development and shadow; this region fills from the release that carries them." />), <SkeletonLines lines={4} />, "Reweighting")}
      </Region>
      <Region id="slices" title="Slices" note="By filer, filer type, CWE, vendor and year; Benjamini-Hochberg at 0.05 within each family">
        {region(() => (isRec(evidence.slices) ? <Slices slices={evidence.slices} /> : <NotYet what="the slices" />), <SkeletonTable rows={6} cols={5} />, "Slices")}
      </Region>
      <Region id="taxonomy" title="The misses, read" note="100 band misses drawn by seed from development, never test">
        {region(() => (isRec(evidence.taxonomy) ? <Taxonomy taxonomy={evidence.taxonomy} /> : <NotYet what="the failure taxonomy" body="The misses are drawn from development and read by hand; this region fills from the release that carries the taxonomy." />), <SkeletonTable rows={6} cols={3} />, "Taxonomy")}
      </Region>
      <p className="mt-xl text-app-sm text-fg-2">
        NVD labels are a selected sample, the filer score favors filers who score, KEV is a lower bound, and one seed is one draw.{" "}
        <Link href="/app/limits">The limits page says what each number cannot show.</Link>
      </p>
    </>
  );
}
