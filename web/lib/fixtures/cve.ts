/**
 * FIXTURE. The view shapes of lib/fixtures/api.ts, made by the same adapters the console uses
 * (lib/api/adapt.ts), for the unit tests and the /design specimen. CVE-2099-0001 does not exist and
 * data_version says "fixture" so every page that shows this record says so. Nothing here is data.
 */
import { toCve, toSummary, toTimeline } from "../api/adapt";
import type { Cve, CveSummary, Timeline } from "../api/view";
import { API_CVE, API_SUMMARIES, API_TIMELINE, FIXTURE_ID } from "./api";

export { FIXTURE_ID };
export const FIXTURE_NOTE = "Fixture: invented values in the API's shape. CVE-2099-0001 is not a real CVE.";

/** The moment the fixture is drawn at, so a wait that is still open has a fixed length. */
export const FIXTURE_NOW = "2026-11-07T12:00:00Z";

export const TIMELINE_FIXTURE: Timeline = { ...toTimeline(API_TIMELINE), now: FIXTURE_NOW };

export const CVE_FIXTURE: Cve = toCve(API_CVE);

export const SUMMARY_FIXTURE: CveSummary[] = API_SUMMARIES.map(toSummary);
