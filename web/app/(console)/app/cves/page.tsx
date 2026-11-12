import type { Metadata } from "next";
import { Suspense } from "react";
import { CveBrowser } from "@/components/console/cve-browser";
import { PageHead } from "@/components/console/page-head";
import { Loading, SkeletonTable } from "@/components/console/region";

export const metadata: Metadata = { title: "CVEs", description: "Every CVE the API serves, filtered in the address bar, with a column chooser." };

export default function CvesPage() {
  return (
    <>
      <PageHead title="CVEs">Every CVE the API serves. The filters live in the address bar, so a filtered view is a link you can send.</PageHead>
      <Suspense
        fallback={
          <Loading label="the CVE filters">
            <SkeletonTable rows={10} cols={7} />
          </Loading>
        }
      >
        <CveBrowser />
      </Suspense>
    </>
  );
}
