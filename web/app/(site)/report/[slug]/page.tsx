import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { DocView } from "@/components/site/doc-view";
import { readReport, reportSources } from "@/lib/docs";

type Props = { params: Promise<{ slug: string }> };

export const dynamicParams = false;

export function generateStaticParams() {
  return reportSources().map((r) => ({ slug: r.slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const doc = readReport(slug);
  return doc ? { title: doc.title, description: doc.lead } : { title: "Report" };
}

export default async function ReportPage({ params }: Props) {
  const { slug } = await params;
  const doc = readReport(slug);
  if (!doc) notFound();
  return <DocView doc={doc} back={{ href: "/report", label: "All of the report" }} />;
}
