import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";
import "./globals.css";
import { fontBody, fontDisplay, fontMono } from "./fonts";
import { Providers } from "@/components/providers";
import { THEME_SCRIPT } from "@/components/theme-script";

export const metadata: Metadata = {
  title: { default: "unscheduled", template: "%s | unscheduled" },
  description: "Triage for the CVEs the NVD no longer analyzes: every fact dated by its source, and matched to an SBOM.",
};

export const viewport: Viewport = { width: "device-width", initialScale: 1 };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={`${fontDisplay.variable} ${fontBody.variable} ${fontMono.variable}`} suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
