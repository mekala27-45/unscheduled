import type { Metadata } from "next";
import { RunsView } from "@/components/console/runs-view";

export const metadata: Metadata = {
  title: "Triage runs",
  description: "Every triage run: the CVE as known on its day, the drafted patch plan and early warning, each claim checked, and what waits for a person.",
};

export default function RunsPage() {
  return <RunsView />;
}
