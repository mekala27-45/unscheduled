import type { Metadata } from "next";
import Link from "next/link";
import { DocList } from "@/components/site/doc-view";
import { Mast } from "@/components/site/mast";
import { SiteNav } from "@/components/site/site-nav";
import { readManifest } from "@/lib/build-data";
import { readReports } from "@/lib/docs";
import { formatDate } from "@/lib/format";

export const metadata: Metadata = {
  title: "Report",
  description: "The backlog in words and numbers, the discovery memo, the legacy memo, the signed criteria and the data card, each rendered from the manifest.",
};

export default function ReportIndex() {
  const reports = readReports();
  const manifest = readManifest();
  const asOf = manifest.state === "ok" ? formatDate(manifest.value.as_of, "long") : null;
  return (
    <div className="site">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <SiteNav banner={<span>Each document is rendered from results/manifest.json, and CI fails if the text and the manifest differ.</span>} />
      <main id="main" tabIndex={-1} className="container docs">
        <div className="docs__head">
          <h1>Report</h1>
          <p className="lead">
            What the NVD change means, measured from the lake{asOf ? `, with data as of ${asOf}` : ""}. The charts behind each question are in the{" "}
            <Link href="/app/backlog">console</Link>.
          </p>
        </div>
        {reports.length ? (
          <DocList docs={reports} base="/report" />
        ) : (
          <p className="lead">No report has been rendered yet. The build writes report/*.md from the manifest.</p>
        )}
      </main>
      <Mast />
    </div>
  );
}
