import type { Metadata } from "next";
import { Suspense } from "react";
import { ModelsView } from "@/components/console/models-view";

export const metadata: Metadata = {
  title: "Models",
  description: "The Phase 2 models with their floors: C1 and C2 with intervals and verdicts, calibration, conformal sets, slices and the misses read by hand.",
};

export default function ModelsPage() {
  return (
    <Suspense>
      <ModelsView />
    </Suspense>
  );
}
