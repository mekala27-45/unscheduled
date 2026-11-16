import {
  ActivityIcon,
  BarChart3Icon,
  BoxesIcon,
  BrainCircuitIcon,
  DatabaseIcon,
  FileCheck2Icon,
  FileSearchIcon,
  InboxIcon,
  ListIcon,
  ScaleIcon,
  ScanSearchIcon,
  SearchIcon,
  WorkflowIcon,
  type LucideIcon,
} from "lucide-react";

/** One lucide icon per console destination, beside its word, never alone. */
export const ICONS: Record<string, LucideIcon> = {
  "/app": SearchIcon,
  "/app/cves": ListIcon,
  "/app/backlog": BarChart3Icon,
  "/app/products": BoxesIcon,
  "/app/match": ScanSearchIcon,
  "/app/runs": WorkflowIcon,
  "/app/inbox": InboxIcon,
  "/app/search": FileSearchIcon,
  "/app/data": DatabaseIcon,
  "/app/models": BrainCircuitIcon,
  "/app/criteria": FileCheck2Icon,
  "/status": ActivityIcon,
  "/app/limits": ScaleIcon,
};
