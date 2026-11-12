import type { ReactNode } from "react";
import { ConsoleShell } from "@/components/console/shell";
import { Mast } from "@/components/site/mast";

export default function ConsoleLayout({ children }: { children: ReactNode }) {
  return <ConsoleShell footer={<Mast variant="app" />}>{children}</ConsoleShell>;
}
