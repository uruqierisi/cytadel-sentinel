import { describe, test, expect } from "vitest";
import { evaluateAuthorization, evaluateScanWindow, evaluateProductionGate } from "./governance.js";
import { buildRoeTemplate, roeInputFromScope } from "./roe.js";
import { ScopeSchema } from "../config/schema.js";

const base = {
  name: "acme", authorized_by: "sec@client", authorization_ref: "CT-42",
  in_scope: { domains: ["127.0.0.1"] }, allow_destructive: true,
};
const scopeWith = (extra: Record<string, unknown>) => ScopeSchema.parse({ ...base, ...extra });

describe("authorization window (WP6)", () => {
  const inside = scopeWith({ authorization_window: { start: "2026-08-18T00:00:00Z", end: "2026-08-19T00:00:00Z" } });

  test("destructive run WITHIN the window is allowed", () => {
    const d = evaluateAuthorization(inside, true, new Date("2026-08-18T12:00:00Z"));
    expect(d.allowed).toBe(true);
  });
  test("destructive run BEFORE the window is refused", () => {
    const d = evaluateAuthorization(inside, true, new Date("2026-08-17T23:00:00Z"));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/before start/);
  });
  test("destructive run AFTER the window is refused", () => {
    const d = evaluateAuthorization(inside, true, new Date("2026-08-20T00:00:00Z"));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/after end/);
  });
  test("destructive run with NO window is refused", () => {
    const d = evaluateAuthorization(scopeWith({}), true, new Date());
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/no authorization_window/);
  });
  test("non-destructive run does not require a window", () => {
    expect(evaluateAuthorization(scopeWith({}), false, new Date()).allowed).toBe(true);
  });
});

describe("scan window / RoE (WP6)", () => {
  const sw = scopeWith({ scan_window: { days: [1, 2, 3, 4, 5], start_hour: 20, end_hour: 24 } });
  test("outside allowed hours is refused (destructive)", () => {
    // A Monday at 10:00 local — hour 10 not in [20,24)
    const d = evaluateScanWindow(sw, true, new Date(2026, 7, 17, 10, 0, 0));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/scan window/);
  });
  test("inside allowed hours is allowed", () => {
    const d = evaluateScanWindow(sw, true, new Date(2026, 7, 17, 21, 0, 0)); // Mon 21:00
    expect(d.allowed).toBe(true);
  });
});

describe("production gate (WP6)", () => {
  const prod = scopeWith({ environment: "production" });
  test("production + destructive + NOT confirmed => injection blocked", () => {
    const g = evaluateProductionGate(prod, true, false);
    expect(g.blocked).toBe(true);
    expect(g.reason).toMatch(/--i-understand-production/);
  });
  test("production + destructive + confirmed => allowed", () => {
    expect(evaluateProductionGate(prod, true, true).blocked).toBe(false);
  });
  test("staging is never blocked", () => {
    expect(evaluateProductionGate(scopeWith({ environment: "staging" }), true, false).blocked).toBe(false);
  });
});

describe("ROE / Authorization Letter template (WP6)", () => {
  test("renders a fillable ROE with engagement + scope + window", () => {
    const scope = scopeWith({
      client: "Acme Corp", environment: "production", emergency_contact: "ops@acme (24/7)",
      authorization_window: { start: "2026-08-18T20:00:00Z", end: "2026-08-19T06:00:00Z" },
    });
    const md = buildRoeTemplate(roeInputFromScope(scope));
    expect(md).toContain("Rules of Engagement & Authorization Letter");
    expect(md).toContain("Acme Corp");
    expect(md).toContain("CT-42"); // authorization ref
    expect(md).toContain("2026-08-18T20:00:00Z"); // window
    expect(md).toContain("PRODUCTION");
    expect(md).toContain("ops@acme (24/7)");
    expect(md).toContain("Signature"); // sign-off table
  });
  test("leaves [BRACKETED] placeholders when fields are missing", () => {
    const md = buildRoeTemplate(roeInputFromScope(scopeWith({})));
    expect(md).toContain("[CLIENT / ORGANISATION NAME]");
  });
});
