import { defineConfig, devices } from "@playwright/test";

/**
 * Every route at 390 and 1440 pixels, in the light and the dark theme. The site is built with
 * NEXT_PUBLIC_API_URL=http://api.unscheduled.test and every request to it is answered by the tests,
 * so no test needs a live API. PW_CHROMIUM lets a machine with its own Chromium skip the download.
 */
const PORT = Number(process.env.PORT ?? 3210);
const executablePath = process.env.PW_CHROMIUM || undefined;
const launchOptions = executablePath ? { executablePath } : {};

const desktop = { viewport: { width: 1440, height: 900 }, launchOptions };
const phone = { ...devices["Pixel 7"], viewport: { width: 390, height: 844 }, deviceScaleFactor: 1, launchOptions };

export default defineConfig({
  testDir: "tests/e2e",
  fullyParallel: true,
  workers: 2,
  timeout: 60_000,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"], ["json", { outputFile: "test-results/report.json" }]],
  use: { baseURL: `http://127.0.0.1:${PORT}`, trace: "retain-on-failure" },
  projects: [
    { name: "desktop-light", use: { ...desktop, colorScheme: "light" } },
    { name: "desktop-dark", use: { ...desktop, colorScheme: "dark" } },
    { name: "phone-light", use: { ...phone, colorScheme: "light" } },
    { name: "phone-dark", use: { ...phone, colorScheme: "dark" } },
  ],
  webServer: {
    command: `pnpm start -p ${PORT} -H 127.0.0.1`,
    url: `http://127.0.0.1:${PORT}/`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
