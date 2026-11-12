import type { Metadata } from "next";
import { Suspense } from "react";
import { SearchHome } from "@/components/console/search-home";

export const metadata: Metadata = { title: "Search", description: "Look up any CVE with its full history, and the last 24 hours of new CVEs, KEV listings and NVD analyses." };

export default function SearchPage() {
  return (
    <Suspense>
      <SearchHome />
    </Suspense>
  );
}
