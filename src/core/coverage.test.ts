import { describe, test, expect } from "vitest";
import { newCoverage, coverageLimitations } from "./coverage.js";

describe("coverageLimitations (WP4)", () => {
  test("endpoint cap that dropped 568 URLs is a named limitation with the number", () => {
    const cov = newCoverage();
    cov.caps.push({ name: "endpoint cap", cap: 300, dropped: 568, detail: "2 host(s)" });
    const lims = coverageLimitations(cov);
    expect(lims.some((l) => /endpoint cap/i.test(l) && l.includes("568") && l.includes("300"))).toBe(true);
  });

  test("degraded auth is a prominent auth-coverage limitation", () => {
    const cov = newCoverage();
    cov.auth = { state: "degraded", mode: "form_login" };
    const lims = coverageLimitations(cov);
    expect(lims.some((l) => /DEGRADED/i.test(l) && /login/i.test(l))).toBe(true);
  });

  test("injection skipped (destructive gate) is surfaced", () => {
    const cov = newCoverage();
    cov.injection = { get: 0, post: 0, ran: false, skippedReason: "destructive gate closed" };
    const lims = coverageLimitations(cov);
    expect(lims.some((l) => /injection.*NOT performed/i.test(l))).toBe(true);
  });

  test("ran but no POST bodies tested is surfaced", () => {
    const cov = newCoverage();
    cov.injection = { get: 5, post: 0, ran: true };
    expect(coverageLimitations(cov).some((l) => /POST\/PUT/i.test(l))).toBe(true);
  });

  test("WP2 discovery notes (no OpenAPI, JS asset count) appear", () => {
    const cov = newCoverage();
    cov.notes.push("OpenAPI: probed 6 location(s), no parseable spec found", "JS assets analysed: 3");
    const lims = coverageLimitations(cov);
    expect(lims.some((l) => /no parseable spec/i.test(l))).toBe(true);
    expect(lims.some((l) => /JS assets analysed: 3/.test(l))).toBe(true);
  });

  test("a clean authenticated run with no caps has no limitations", () => {
    const cov = newCoverage();
    cov.auth = { state: "authenticated", mode: "form_login" };
    cov.injection = { get: 4, post: 2, ran: true };
    expect(coverageLimitations(cov)).toEqual([]);
  });
});
