import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import type { NextConfig } from "next";

/**
 * Two facts the footer prints on every route, fixed when the site is built: the date of the data
 * release (results/manifest.json, if one exists) and the web version. Read here so no page reads a
 * file at request time.
 */
function dataAsOf(): string {
  const file = path.resolve(process.cwd(), "..", "results", "manifest.json");
  if (!existsSync(file)) return "";
  try {
    const asOf = (JSON.parse(readFileSync(file, "utf8")) as { as_of?: unknown }).as_of;
    return typeof asOf === "string" ? asOf : "unreadable";
  } catch {
    return "unreadable";
  }
}

function webVersion(): string {
  try {
    return (JSON.parse(readFileSync(path.resolve(process.cwd(), "package.json"), "utf8")) as { version?: string }).version ?? "unknown";
  } catch {
    return "unknown";
  }
}

const config: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  env: {
    UNSCHED_DATA_AS_OF: dataAsOf(),
    UNSCHED_WEB_VERSION: webVersion(),
  },
};

export default config;
