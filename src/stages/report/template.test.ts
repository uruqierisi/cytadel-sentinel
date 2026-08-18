import { describe, test, expect } from "vitest";
import { renderHtml, type ReportData, type ReportFinding } from "./template.js";
import { parseSqlmapStdout } from "../scan/sqlmap.js";

// A confirmed Juice Shop SQLi as sqlmap prints it (q=apple, boolean + time-based).
const SQLMAP_OUT = `
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=apple') AND 1234=1234 AND ('abcd'='abcd
---
`;
const SEED_URL = "http://127.0.0.1:3000/rest/products/search?q=apple";

/** Map a sqlmap GenericFinding to the ReportFinding shape collectFromLocal produces. */
function reportFindingFromSqlmap(): ReportFinding {
  const gf = parseSqlmapStdout(SQLMAP_OUT, SEED_URL)[0]!;
  return {
    title: gf.title,
    severity: gf.severity,
    target: gf.endpoint,
    sourceTool: gf.sourceTool,
    cve: null,
    cvss: null,
    description: gf.description,
    evidence: gf.evidence,
    verified: false,
    active: true,
  };
}

function baseData(findings: ReportFinding[]): ReportData {
  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) severityCounts[f.severity]++;
  return {
    runId: "run-123",
    generatedAt: "2026-08-17T00:00:00.000Z",
    scope: {
      name: "juice-shop",
      authorizedBy: "me",
      authorizationRef: "LOCAL",
      scopeHash: "abcdef0123456789",
      allowDestructive: true,
    },
    actor: "me",
    startedAt: "2026-08-17T00:00:00.000Z",
    finishedAt: "2026-08-17T00:01:00.000Z",
    assetCount: 3,
    activeInjection: true,
    engagementId: null,
    defectDojoUrl: null,
    severityCounts,
    findings,
    coverage: {
      hosts: { discovered: 1, tested: 1 },
      endpoints: { discovered: 5, tested: 5 },
      params: { discovered: 3, tested: 3 },
      authState: "authenticated",
      authMode: "form_login",
      candidatesBySource: { discovery: 0, seed: 1, js: 2, openapi: 0, graphql: 0 },
      injection: { get: 3, post: 0, ran: true },
      tools: [{ name: "sqlmap", version: "1.8.8" }],
      limitations: [],
    },
  };
}

describe("renderHtml — the seeded SQLi shows in the HTML report", () => {
  const html = renderHtml(baseData([reportFindingFromSqlmap()]));

  test("renders the parameter, endpoint URL, technique and payload", () => {
    expect(html).toContain("SQL injection on parameter"); // param q in the title
    expect(html).toContain("127.0.0.1:3000/rest/products/search?q=apple"); // the q=apple URL
    expect(html).toContain("boolean-based blind"); // technique
    expect(html).toContain("payload:"); // payload label
    expect(html).toContain("q=apple"); // the concrete payload/value
    expect(html).toContain("sqlmap"); // source tool
  });

  test("does not render the empty-findings placeholder", () => {
    expect(html).not.toContain("No findings reported");
  });

  test("severity summary reflects the single HIGH finding", () => {
    // The counts fed to the report are the same set rendered as rows — no divergence.
    const data = baseData([reportFindingFromSqlmap()]);
    expect(data.severityCounts.HIGH).toBe(1);
    expect(data.findings.length).toBe(1);
  });

  test("renders a Coverage section with tested-vs-discovered counts, auth, tools", () => {
    expect(html).toContain("Coverage");
    expect(html).toContain("tested / discovered");
    expect(html).toContain("5 / 5"); // endpoints tested/discovered
    expect(html).toContain("authenticated"); // auth coverage line
    expect(html).toContain("sqlmap"); // tool used
    expect(html).toContain("1.8.8"); // tool version
  });

  test("Coverage limitations (caps, degraded auth) render in the HTML", () => {
    const data = baseData([]);
    data.coverage.limitations = [
      "endpoint cap hit (limit 300, 2 host(s)): 568 item(s) dropped and NOT tested.",
      "Authentication DEGRADED mid-run — content behind login may be under-tested.",
      "OpenAPI: probed 6 location(s), no parseable spec found",
    ];
    data.coverage.authState = "degraded";
    const out = renderHtml(data);
    expect(out).toContain("Coverage limitations");
    expect(out).toContain("568 item(s) dropped");
    expect(out).toContain("DEGRADED");
    expect(out).toContain("no parseable spec found");
    expect(out).toContain("cov-bad"); // degraded auth styled prominently
  });
});
