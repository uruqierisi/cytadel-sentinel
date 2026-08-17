import { describe, test, expect } from "vitest";
import { buildGenericFindingsDoc, type GenericFinding } from "./generic.js";
import { parseGeneric } from "../normalize/parsers.js";

const SQLI: GenericFinding = {
  sourceTool: "sqlmap",
  title: 'SQL Injection (boolean-based blind) on parameter "q"',
  description: 'sqlmap confirmed boolean-based blind SQL injection on parameter "q" (GET) — back-end DBMS: SQLite.',
  severity: "HIGH",
  cwe: 89,
  endpoint: "http://127.0.0.1:3000/rest/products/search?q=apple",
  uniqueId: "abc123",
  evidence: "technique: OR boolean-based blind — payload: q=apple') OR 5539=5539 — DBMS: SQLite",
};

// DefectDojo's Generic Findings Import serializer rejects any unknown key with a
// 400, so the payload must contain ONLY these standard fields.
const DD_ALLOWED = new Set([
  "title",
  "description",
  "severity",
  "date",
  "cwe",
  "file_path",
  "unique_id_from_tool",
  "dynamic_finding",
  "static_finding",
  "endpoints",
]);

describe("buildGenericFindingsDoc — DefectDojo-safe payload (Fix A)", () => {
  const doc = buildGenericFindingsDoc([SQLI]);
  const finding = doc.findings[0]!;

  test("emits ONLY DefectDojo-allowlisted fields (no sentinel_* keys)", () => {
    for (const key of Object.keys(finding)) {
      expect(DD_ALLOWED.has(key)).toBe(true);
    }
    expect(Object.keys(finding)).not.toContain("sentinel_tool");
    expect(Object.keys(finding)).not.toContain("sentinel_evidence");
  });

  test("evidence is folded into the standard description so it isn't lost", () => {
    expect(String(finding.description)).toContain("payload: q=apple')");
    expect(String(finding.description)).toContain("DBMS: SQLite");
  });

  test("round-trips through parseGeneric: tool from fallback, evidence recovered", () => {
    const unified = parseGeneric(JSON.stringify(doc), "sqlmap");
    expect(unified.length).toBe(1);
    const u = unified[0]!;
    expect(u.sourceTool).toBe("sqlmap");
    expect(u.name).toContain('parameter "q"');
    expect(u.target).toBe("http://127.0.0.1:3000/rest/products/search?q=apple");
    expect(u.evidence).toContain("payload: q=apple')");
    expect(u.severity).toBe("HIGH");
  });
});
