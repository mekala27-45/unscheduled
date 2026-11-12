import { defineConfig } from "@playwright/test";
import base from "./playwright.config";

/** The look review: the screens a person signs off, at 1440 by 900 and 390 by 844, light and dark. */
export default defineConfig({
  ...base,
  testDir: "tests/review",
  retries: 0,
  reporter: [["list"]],
});
