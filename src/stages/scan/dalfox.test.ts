import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, test, expect } from "vitest";
import { dalfoxPocToFinding } from "./dalfox.js";
import { parseJsonArrayLoose } from "../../lib/parse.js";
import { parseGeneric } from "../normalize/parsers.js";

const fixture = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`./__fixtures__/${name}`, import.meta.url)), "utf8");

/**
 * The regression from the live run: dalfox emitted a JSON ARRAY, was
 * SIGTERM-killed at its timeout AFTER printing 2 complete PoC objects, so the
 * array had an opening "[" but NO closing "]". The old parser saw invalid JSON
 * and reported "dalfox found no XSS" — the 2 High findings were discarded.
 */
describe("dalfox partial capture — unterminated JSON array from a kill", () => {
  test("recovers BOTH complete PoC objects before the cut", () => {
    const raw = fixture("dalfox-truncated.json");
    // Sanity: the fixture really is a truncated array (no closing bracket).
    expect(raw.trimEnd().endsWith("]")).toBe(false);
    expect(raw.trimStart().startsWith("[")).toBe(true);

    const pocs = parseJsonArrayLoose<Record<string, unknown>>(raw);
    expect(pocs.length).toBe(2);

    const findings = pocs.map(dalfoxPocToFinding);
    expect(findings.length).toBe(2);

    for (const f of findings) {
      expect(f.sourceTool).toBe("dalfox");
      expect(f.severity).toBe("HIGH");
      expect(f.cwe).toBe(79);
      // The /Search.asp URL and the tfSearch param are wired through.
      expect(f.endpoint).toContain("/Search.asp");
      expect(f.title).toContain('parameter "tfSearch"');
      // payload AND evidence are populated (they came through empty before).
      expect(f.evidence).toBeTruthy();
      expect(f.evidence).toContain("payload:");
      expect(f.evidence).toContain("evidence:");
    }

    // Two distinct PoCs (different inject types/payloads) stay distinct.
    const ids = new Set(findings.map((f) => f.uniqueId));
    expect(ids.size).toBe(2);
  });

  test("end-to-end: truncated dalfox output reaches report.json shape with 2 High XSS", () => {
    // Mirror the real pipeline: parse PoCs -> GenericFinding -> the generic
    // import file shape -> normalize's parseGeneric (what feeds report.json).
    const pocs = parseJsonArrayLoose<Record<string, unknown>>(fixture("dalfox-truncated.json"));
    const findings = pocs.map(dalfoxPocToFinding);

    const genericDoc = JSON.stringify({
      findings: findings.map((f) => ({
        title: f.title,
        description: f.description,
        severity: "High",
        cwe: f.cwe,
        file_path: f.endpoint,
        unique_id_from_tool: f.uniqueId,
        endpoints: [f.endpoint],
        sentinel_tool: f.sourceTool,
        sentinel_evidence: f.evidence ?? "",
      })),
    });

    const unified = parseGeneric(genericDoc, "dalfox");
    expect(unified.length).toBe(2);
    for (const u of unified) {
      expect(u.severity).toBe("HIGH");
      expect(u.sourceTool).toBe("dalfox");
      expect(u.target).toContain("/Search.asp");
      expect(u.name).toContain("tfSearch");
      expect(u.evidence).toBeTruthy();
    }
  });
});

describe("parseJsonArrayLoose — array-repair variants", () => {
  test("strict: a complete array parses", () => {
    expect(parseJsonArrayLoose("[{\"a\":1},{\"a\":2}]").length).toBe(2);
  });

  test("repair: complete objects but trailing comma and missing bracket", () => {
    // dalfox got killed right after writing a comma, before the next object.
    const out = parseJsonArrayLoose<{ a: number }>('[{"a":1},{"a":2},');
    expect(out.map((o) => o.a)).toEqual([1, 2]);
  });

  test("mid-object cut: keeps the complete objects, drops the partial one", () => {
    const out = parseJsonArrayLoose<{ a: number }>('[{"a":1},{"a":2},{"a":3,"b":');
    expect(out.map((o) => o.a)).toEqual([1, 2]);
  });

  test("braces inside string values don't confuse the scanner", () => {
    // Two complete objects whose string values contain '{'/'}'/']'; array unterminated.
    const out = parseJsonArrayLoose<{ p: string }>('[{"p":"a{b}c"},{"p":"x}y]{z"}');
    expect(out.length).toBe(2);
    expect(out[0]!.p).toBe("a{b}c");
    expect(out[1]!.p).toBe("x}y]{z");
  });

  test("empty / whitespace yields no findings", () => {
    expect(parseJsonArrayLoose("")).toEqual([]);
    expect(parseJsonArrayLoose("   \n ")).toEqual([]);
  });
});
