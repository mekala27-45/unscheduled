/** A CVE id as the CVE Program writes it: CVE, the year, and four or more digits. */
const CVE_RE = /^CVE-(\d{4})-(\d{4,})$/;
const CWE_RE = /^CWE-\d{1,5}$/;

export function normalizeCveId(input: string | null | undefined): string | null {
  if (!input) return null;
  const id = input.trim().toUpperCase().replace(/\s+/g, "");
  const m = CVE_RE.exec(id);
  if (!m) return null;
  const year = Number(m[1]);
  return year >= 1999 ? id : null;
}

export function normalizeCweId(input: string | null | undefined): string | null {
  if (!input) return null;
  const id = input.trim().toUpperCase();
  return CWE_RE.test(id) ? id : null;
}

export function cveOrgUrl(id: string): string {
  return `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`;
}
