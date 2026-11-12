import type { Metadata } from "next";
import Link from "next/link";
import { PageHead } from "@/components/console/page-head";

export const metadata: Metadata = { title: "Limits", description: "What a security lead and a data lead would question about this console, and what the build did about each." };

const SECURITY = [
  ["The customer is fictional.", "Velloran Systems does not exist. Six public open source repositories stand in for its products, each pinned to one commit, and every page that shows one names it as a stand-in. The exposure describes those repositories, not a company."],
  ["KEV is a lower bound.", "CISA lists what it has confirmed as exploited. A CVE missing from KEV may still be exploited, so the console never reads absence from KEV as safety."],
  ["The CPE contrast is one scanner.", "Grype stands in for scanners that match by NVD CPE names. Another CPE scanner could find a little more or less; the share it misses is measured for Grype only."],
  ["The legacy script is a fixture.", "It was written for this build in the style of a nightly job, says so in its header, and never runs against the live NVD."],
  ["Nothing here is an official score.", "Every value names who published it and since when. In this phase unscheduled publishes no score of its own."],
];

const DATA = [
  ["Filer scores come from parties with incentives.", "A vendor scoring its own CVE may score low; a research platform may score high. Q4 measures agreement with the NVD, by filer type, before either is used as a label."],
  ["NVD labels after April 2026 are a selected sample.", "The NVD now analyzes the CVEs it ranks first, so its analyzed CVEs are not like the rest. Q8 measures how different, and Phase 2 reweights for it."],
  ["History before 2017 is dated by rule.", "The NVD change history starts in 2017. Older facts are dated from publication or from the first fetch, and each fact records the rule that dated it."],
  ["EPSS is kept only at offsets.", "Scores at 0, 1, 7, 30 and 90 days after publication, and every day for KEV listed CVEs. That is a declared subset, not the whole history."],
  ["Time, not chance.", "The month is split by publication date. There is no random split anywhere, so nothing downstream can learn next year's vendor mix."],
];

function List({ items }: { items: string[][] }) {
  return (
    <ul>
      {items.map(([lead, body]) => (
        <li key={lead}>
          <strong className="font-medium text-fg">{lead}</strong> {body}
        </li>
      ))}
    </ul>
  );
}

export default function LimitsPage() {
  return (
    <>
      <PageHead title="Limits">The objections a security lead and a data lead would raise about every screen in this console, and what the build did about each.</PageHead>
      <div className="prose">
        <h2>What a security lead would question</h2>
        <List items={SECURITY} />
        <h2>What a data lead would question</h2>
        <List items={DATA} />
        <p className="mt-xl text-app-sm text-fg-muted">
          The evidence pages say the same beside their numbers. <Link href="/app/backlog">The backlog</Link> and <Link href="/app/products">the products</Link> link back here.
        </p>
      </div>
    </>
  );
}
