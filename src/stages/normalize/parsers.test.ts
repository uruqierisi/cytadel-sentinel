import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, test, expect } from "vitest";
import { parseNuclei, parseGeneric } from "./parsers.js";
import { dedupeKey } from "./types.js";

const fixture = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`./__fixtures__/${name}`, import.meta.url)), "utf8");

describe("parseNuclei — partial capture (truncated mid-stream)", () => {
  // Proves BUG 1's fix: a nuclei.jsonl killed mid-write still yields the
  // complete findings that landed before the truncation point.
  test("parses complete lines and skips the truncated final line", () => {
    const content = fixture("nuclei-truncated.jsonl");
    const findings = parseNuclei(content);

    // 3 complete JSONL records; the 4th (truncated) is skipped, not fatal.
    expect(findings.length).toBe(3);

    const ids = findings.map((f) => f.templateId);
    expect(ids).toContain("waf-detect");
    expect(ids).toContain("tech-detect");
    expect(ids).toContain("microsoft-iis-version");

    // Findings are real, usable records — target + name resolved.
    for (const f of findings) {
      expect(f.sourceTool).toBe("nuclei");
      expect(f.target).toContain("testasp.vulnweb.com");
      expect(f.name.length).toBeGreaterThan(0);
      expect(() => dedupeKey(f)).not.toThrow();
    }
  });

  test("an entirely empty capture yields no findings (no throw)", () => {
    expect(parseNuclei("")).toEqual([]);
    expect(parseNuclei("\n\n")).toEqual([]);
  });

  test("a capture that is ONLY a truncated line still does not throw", () => {
    expect(parseNuclei('{"template-id":"partial","info":{"name":"x"')).toEqual([]);
  });
});

describe("parseGeneric — dalfox/sqlmap findings", () => {
  test("maps DefectDojo Generic Findings Import JSON into unified findings", () => {
    const doc = JSON.stringify({
      findings: [
        {
          title: 'SQL injection on parameter "id" (GET)',
          description: "sqlmap confirmed SQL injection.",
          severity: "High",
          cwe: 89,
          file_path: "http://testasp.vulnweb.com/showforum.asp?id=0",
          unique_id_from_tool: "abc123",
          endpoints: ["http://testasp.vulnweb.com/showforum.asp?id=0"],
          sentinel_tool: "sqlmap",
          sentinel_evidence: "boolean-based blind",
        },
      ],
    });
    const findings = parseGeneric(doc, "sqlmap");
    expect(findings.length).toBe(1);
    expect(findings[0]!.sourceTool).toBe("sqlmap");
    expect(findings[0]!.severity).toBe("HIGH");
    expect(findings[0]!.target).toContain("showforum.asp");
    expect(findings[0]!.evidence).toBe("boolean-based blind");
  });

  test("tolerates malformed JSON without throwing", () => {
    expect(parseGeneric("{ not json", "dalfox")).toEqual([]);
  });
});
