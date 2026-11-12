"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { normalizeCveId } from "@/lib/cve";

/**
 * The close: a CVE id goes straight to its ruler. Without script the form sends ?q= to the console
 * search, which opens the same page.
 */
export function LookupForm() {
  const router = useRouter();
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const submit = (e: FormEvent) => {
    const id = normalizeCveId(value);
    e.preventDefault();
    if (!id) {
      setError("Write the id as CVE, the year and the number: CVE-YYYY-NNNNN.");
      return;
    }
    router.push(`/app/cves/${id}`);
  };
  return (
    <form className="lookup" action="/app" method="get" onSubmit={submit} role="search" aria-label="Look up a CVE">
      <label className="label" htmlFor="close-id">
        CVE id
      </label>
      <div className="lookup__row">
        <input
          id="close-id"
          name="q"
          className="field field--mono"
          type="search"
          autoComplete="off"
          spellCheck={false}
          placeholder="CVE-YYYY-NNNNN"
          value={value}
          aria-invalid={error ? true : undefined}
          aria-describedby="close-id-help"
          onChange={(e) => {
            setValue(e.target.value);
            setError(null);
          }}
        />
        <button type="submit" className="key key--primary key--lg">
          Look up a CVE
        </button>
      </div>
      <p id="close-id-help" className="help" data-tone={error ? "error" : undefined} aria-live="polite">
        {error ?? ""}
      </p>
    </form>
  );
}
