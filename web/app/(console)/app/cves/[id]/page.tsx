import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Suspense } from "react";
import { CveDetail } from "@/components/console/cve-detail";
import { PageHead } from "@/components/console/page-head";
import { EmptyState, Loading, SkeletonChart } from "@/components/console/region";
import { normalizeCveId } from "@/lib/cve";

type Props = { params: Promise<{ id: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { id } = await params;
  const cve = normalizeCveId(decodeURIComponent(id));
  return { title: cve ?? "Not a CVE id", description: cve ? `${cve}: every dated event on one ruler, and every field with its source and since when.` : undefined };
}

export default async function CvePage({ params }: Props) {
  const { id: raw } = await params;
  const id = normalizeCveId(decodeURIComponent(raw));
  if (!id) {
    return (
      <>
        <PageHead title="Not a CVE id" />
        <EmptyState
          title={`"${decodeURIComponent(raw).slice(0, 40)}" is not a CVE id`}
          body="A CVE id is CVE, the year and a number of four digits or more, for example CVE-YYYY-NNNNN."
          action={{ label: "Back to search", href: "/app" }}
        />
        <p className="mt-md text-app-sm">
          <Link href="/app/cves">Or browse every CVE</Link>
        </p>
      </>
    );
  }
  if (id !== raw) redirect(`/app/cves/${id}`);
  return (
    <Suspense
      fallback={
        <Loading label={id}>
          <PageHead title={id} />
          <SkeletonChart />
        </Loading>
      }
    >
      <CveDetail id={id} />
    </Suspense>
  );
}
