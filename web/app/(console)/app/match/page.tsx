import type { Metadata } from "next";
import { MatchView } from "@/components/console/match-view";

export const metadata: Metadata = { title: "Match", description: "Match a CycloneDX or SPDX SBOM against OSV and GitHub advisory ranges; only its digest is kept." };

export default function MatchPage() {
  return <MatchView />;
}
