/**
 * The public sources unscheduled reads, as the Phase 1 plan names them (section 5 and Part 2,
 * read on 7 November 2026). Licence and cadence are the plan's; the fetch time and row count of each
 * come from the locks and the manifest once a source is fetched, never from this file.
 */
export type SourceId = "cvelist" | "nvd" | "kev" | "epss" | "osv" | "ghsa" | "vulnrichment" | "cwe" | "exploits";

export type Source = {
  id: SourceId;
  name: string;
  publisher: string;
  terms: string;
  cadence: string;
  url: string;
};

export const SOURCES: Source[] = [
  { id: "cvelist", name: "CVE List V5", publisher: "CVE Program", terms: "CVE terms", cadence: "hourly", url: "https://github.com/CVEProject/cvelistV5" },
  { id: "nvd", name: "NVD API", publisher: "NIST", terms: "NVD notice", cadence: "daily", url: "https://nvd.nist.gov/developers" },
  { id: "kev", name: "CISA KEV", publisher: "CISA", terms: "CC0 1.0", cadence: "hourly", url: "https://github.com/cisagov/kev-data" },
  { id: "epss", name: "EPSS", publisher: "FIRST", terms: "FIRST terms", cadence: "daily", url: "https://www.first.org/epss/" },
  { id: "osv", name: "OSV", publisher: "OSV.dev", terms: "per source", cadence: "daily", url: "https://osv.dev" },
  { id: "ghsa", name: "GitHub advisories", publisher: "GitHub", terms: "CC BY 4.0", cadence: "daily", url: "https://github.com/github/advisory-database" },
  { id: "vulnrichment", name: "Vulnrichment", publisher: "CISA", terms: "CC0 1.0", cadence: "daily", url: "https://github.com/cisagov/vulnrichment" },
  { id: "cwe", name: "CWE", publisher: "MITRE", terms: "MITRE terms", cadence: "per build", url: "https://cwe.mitre.org" },
  { id: "exploits", name: "Metasploit, Nuclei", publisher: "Rapid7, ProjectDiscovery", terms: "id, date only", cadence: "daily", url: "https://github.com/rapid7/metasploit-framework" },
];

export const SBOM_FORMATS = ["CycloneDX 1.6", "SPDX JSON"];
export const ECOSYSTEMS = ["npm", "PyPI", "Go", "Maven", "crates.io", "RubyGems", "NuGet", "Packagist", "Debian"];

/** Filer types as config/filers.yaml groups them (section 7). */
export const FILER_TYPES = [
  { value: "vendor", label: "Vendor" },
  { value: "open_source", label: "Open source project" },
  { value: "research", label: "Research or bug bounty platform" },
  { value: "national_cert", label: "National CERT" },
  { value: "mitre", label: "MITRE" },
  { value: "other", label: "Other" },
];
