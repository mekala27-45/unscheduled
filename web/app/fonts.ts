import localFont from "next/font/local";

/**
 * The three faces of section 15, self hosted from the Fontsource 5.3.0 packages at build time.
 * Rethink Sans for heads and display figures, Anek Latin for the interface and body, Mononoki for
 * CVE ids, versions, package URLs, digests, code and the field. Each sets an --ff-* variable that
 * styles/tokens.css reads into --font-display, --font-body and --font-outlier.
 */
export const fontDisplay = localFont({
  src: [
    { path: "../node_modules/@fontsource/rethink-sans/files/rethink-sans-latin-500-normal.woff2", weight: "500", style: "normal" },
    { path: "../node_modules/@fontsource/rethink-sans/files/rethink-sans-latin-600-normal.woff2", weight: "600", style: "normal" },
  ],
  variable: "--ff-display",
  display: "swap",
  fallback: ["system-ui", "sans-serif"],
  adjustFontFallback: "Arial",
});

export const fontBody = localFont({
  src: [
    { path: "../node_modules/@fontsource/anek-latin/files/anek-latin-latin-400-normal.woff2", weight: "400", style: "normal" },
    { path: "../node_modules/@fontsource/anek-latin/files/anek-latin-latin-500-normal.woff2", weight: "500", style: "normal" },
  ],
  variable: "--ff-body",
  display: "swap",
  fallback: ["system-ui", "sans-serif"],
  adjustFontFallback: "Arial",
});

export const fontMono = localFont({
  src: [{ path: "../node_modules/@fontsource/mononoki/files/mononoki-latin-400-normal.woff2", weight: "400", style: "normal" }],
  variable: "--ff-mono",
  display: "swap",
  fallback: ["ui-monospace", "monospace"],
  adjustFontFallback: false,
});
