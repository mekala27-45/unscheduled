import {
  ActivityIcon,
  BarChart3Icon,
  BoxesIcon,
  DatabaseIcon,
  FileCheck2Icon,
  ListIcon,
  ScaleIcon,
  ScanSearchIcon,
  SearchIcon,
  type LucideIcon,
} from "lucide-react";

/** One lucide icon per console destination, beside its word, never alone. */
export const ICONS: Record<string, LucideIcon> = {
  "/app": SearchIcon,
  "/app/cves": ListIcon,
  "/app/backlog": BarChart3Icon,
  "/app/products": BoxesIcon,
  "/app/match": ScanSearchIcon,
  "/app/data": DatabaseIcon,
  "/app/criteria": FileCheck2Icon,
  "/status": ActivityIcon,
  "/app/limits": ScaleIcon,
};
