import type { Metadata } from "next";
import { Suspense } from "react";
import { AdvisorySearch } from "@/components/console/advisory-search";
import { Loading, SkeletonLines } from "@/components/console/region";

export const metadata: Metadata = {
  title: "Advisory search",
  description: "The advisory corpus as it was known at the end of a day, each chunk with its document, version and known-from date.",
};

export default function SearchPage() {
  return (
    <Suspense
      fallback={
        <Loading label="the advisory search">
          <SkeletonLines lines={4} />
        </Loading>
      }
    >
      <AdvisorySearch />
    </Suspense>
  );
}
