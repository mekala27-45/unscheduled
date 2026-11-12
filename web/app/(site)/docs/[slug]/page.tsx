import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { DocView } from "@/components/site/doc-view";
import { docSources, readDoc } from "@/lib/docs";

type Props = { params: Promise<{ slug: string }> };

export const dynamicParams = false;

export function generateStaticParams() {
  return docSources().map((d) => ({ slug: d.slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const doc = readDoc(slug);
  return doc ? { title: doc.title, description: doc.lead } : { title: "Docs" };
}

export default async function DocPage({ params }: Props) {
  const { slug } = await params;
  const doc = readDoc(slug);
  if (!doc) notFound();
  return <DocView doc={doc} back={{ href: "/docs", label: "All docs" }} />;
}
