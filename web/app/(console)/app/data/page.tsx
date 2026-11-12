import type { Metadata } from "next";
import { DataView } from "@/components/console/data-view";

export const metadata: Metadata = { title: "Data", description: "Sources, licences, locks, freshness, the run ledger and the quarantine counts." };

export default function DataPage() {
  return <DataView />;
}
