import { CircleCheckIcon, CircleDashedIcon, OctagonAlertIcon, OctagonXIcon, TriangleAlertIcon } from "lucide-react";
import type { ReactNode } from "react";

export type Tone = "good" | "warning" | "serious" | "critical" | "quiet";

const ICON = { good: CircleCheckIcon, warning: TriangleAlertIcon, serious: OctagonAlertIcon, critical: OctagonXIcon, quiet: CircleDashedIcon };

/** Status is a word with one icon in the reserved status colours, never a filled chip and never colour alone. */
export function StatusText({ tone, children }: { tone: Tone; children: ReactNode }) {
  const Icon = ICON[tone];
  return (
    <span className="status" data-tone={tone}>
      <Icon aria-hidden="true" />
      {children}
    </span>
  );
}
