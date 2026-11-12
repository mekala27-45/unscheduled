import type { Metadata } from "next";
import { Suspense } from "react";
import { BacklogView } from "@/components/console/backlog-view";

export const metadata: Metadata = { title: "Backlog", description: "Q1 to Q6: what the NVD stopped analyzing after 15 April 2026, each chart with its table and SQL." };

export default function BacklogPage() {
  return (
    <Suspense>
      <BacklogView />
    </Suspense>
  );
}
