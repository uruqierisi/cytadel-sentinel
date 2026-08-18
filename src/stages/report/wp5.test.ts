import { describe, test, expect } from "vitest";
import { remediationFor } from "./remediation.js";
import { cvssFor, businessImpactFor } from "./cvss.js";
import { diffFindings } from "./retest.js";
import { buildExecutive } from "./executive.js";
import type { ReportFinding, CoverageReport } from "./template.js";

describe("remediation map (WP5)", () => {
  test("a SQLi finding (CWE-89) gets parameterized-query guidance", () => {
    const r = remediationFor({ cwe: 89, sourceTool: "sqlmap" });
    expect(r.summary.toLowerCase()).toContain("parameterized");
    expect(r.guidance.toLowerCase()).toContain("prepared statement");
  });
  test("an XSS finding (CWE-79) gets output-encoding/CSP guidance", () => {
    const r = remediationFor({ cwe: 79 });
    expect(r.guidance.toLowerCase()).toContain("encode");
    expect(r.guidance.toLowerCase()).toContain("csp");
  });
  test("falls back to the source tool, then generic", () => {
    expect(remediationFor({ sourceTool: "dalfox" }).summary.toLowerCase()).toContain("encod");
    expect(remediationFor({}).summary.length).toBeGreaterThan(0);
  });
});

describe("CVSS v3.1 defaults (WP5)", () => {
  test("SQLi -> high score + a v3.1 vector", () => {
    const c = cvssFor({ cwe: 89, severity: "HIGH" });
    expect(c.vector).toMatch(/^CVSS:3\.1\/AV:N/);
    expect(c.score).toBeGreaterThanOrEqual(9);
  });
  test("XSS vector has scope-changed + user-interaction", () => {
    expect(cvssFor({ cwe: 79, severity: "MEDIUM" }).vector).toContain("S:C");
    expect(cvssFor({ cwe: 79, severity: "MEDIUM" }).vector).toContain("UI:R");
  });
  test("business impact is business-language and class-specific", () => {
    expect(businessImpactFor({ cwe: 89, severity: "HIGH" }).toLowerCase()).toContain("database");
  });
});

describe("retest diff (WP5)", () => {
  const cur = [
    { key: "a", severity: "HIGH" as const },  // present in prior at MEDIUM -> regressed
    { key: "b", severity: "HIGH" as const },  // present, same -> present
    { key: "c", severity: "LOW" as const },   // not in prior -> new
  ];
  const prev = [
    { key: "a", severity: "MEDIUM" as const },
    { key: "b", severity: "HIGH" as const },
    { key: "d", severity: "HIGH" as const },  // gone now -> fixed
  ];

  test("computes new / present / fixed / regressed", () => {
    const d = diffFindings(cur, prev);
    expect(d.statusByKey.get("a")).toBe("regressed");
    expect(d.statusByKey.get("b")).toBe("present");
    expect(d.statusByKey.get("c")).toBe("new");
    expect(d.fixed.map((f) => f.key)).toEqual(["d"]);
    expect(d.counts).toEqual({ new: 1, present: 1, regressed: 1, fixed: 1 });
  });
});

describe("executive summary (WP5)", () => {
  const cov: CoverageReport = {
    hosts: { discovered: 1, tested: 1 }, endpoints: { discovered: 10, tested: 8 },
    params: { discovered: 3, tested: 3 }, authState: "authenticated", authMode: "form_login",
    candidatesBySource: {}, injection: { get: 3, post: 0, ran: true }, tools: [], limitations: [],
  };
  const findings: ReportFinding[] = [
    { title: "SQL Injection on parameter q", severity: "HIGH", target: "http://h/search?q=apple",
      sourceTool: "sqlmap", cve: null, cvss: null, description: null, evidence: null, verified: false, active: true,
      cwe: 89, businessImpact: "An attacker could read the database." },
  ];

  test("has a posture, top issues in business terms, and a coverage line", () => {
    const e = buildExecutive(findings, { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 }, cov);
    expect(e.posture.toLowerCase()).toContain("high risk");
    expect(e.topIssues[0]).toContain("SQL Injection");
    expect(e.topIssues[0]).toContain("read the database");
    expect(e.coverageLine.toLowerCase()).toContain("authenticated");
  });
});
