import type { Metadata } from "next";
import { StatusView } from "@/components/console/status-view";

export const metadata: Metadata = { title: "Status", description: "Health and freshness per source, read live from the API." };

export default function StatusPage() {
  return <StatusView />;
}
