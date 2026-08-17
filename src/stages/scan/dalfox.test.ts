import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, test, expect } from "vitest";
import { dalfoxPocToFinding } from "./dalfox.js";
import { buildGenericFindingsDoc, type GenericFinding } from "./generic.js";
import { parseJsonArrayLoose } from "../../lib/parse.js";
import { parseGeneric } from "../normalize/parsers.js";

const nonNull = (fs: Array<GenericFinding | null>): GenericFinding[] =>
  fs.filter((f): f is GenericFinding => f !== null);

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

    const findings = nonNull(pocs.map(dalfoxPocToFinding));
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

  test("end-to-end: dalfox PoCs -> DD-clean generic doc -> report shows param + evidence", () => {
    // Mirror the real pipeline through the ACTUAL doc builder: parse PoCs ->
    // GenericFinding -> buildGenericFindingsDoc -> parseGeneric (feeds report).
    const pocs = parseJsonArrayLoose<Record<string, unknown>>(fixture("dalfox-truncated.json"));
    const findings = nonNull(pocs.map(dalfoxPocToFinding));

    const doc = buildGenericFindingsDoc(findings);
    // Fix A: NO custom sentinel_* keys anywhere in the DD import payload.
    const keys = new Set(doc.findings.flatMap((f) => Object.keys(f)));
    expect(keys.has("sentinel_tool")).toBe(false);
    expect(keys.has("sentinel_evidence")).toBe(false);

    const unified = parseGeneric(JSON.stringify(doc), "dalfox");
    expect(unified.length).toBe(2);
    for (const u of unified) {
      expect(u.severity).toBe("HIGH");
      expect(u.sourceTool).toBe("dalfox"); // from the artifact tool (fallback), not a custom key
      expect(u.target).toContain("/Search.asp");
      // Fix B: the real param and the payload/evidence survive to the report.
      expect(u.name).toContain("tfSearch");
      expect(u.name).not.toContain('parameter ""');
      expect(u.evidence).toBeTruthy();
      expect(u.evidence).toContain("payload:");
    }
  });
});

describe("dalfoxPocToFinding — never emits an empty-parameter finding (Bug 2)", () => {
  test("a real parameterized hit names the param and URL, stays High", () => {
    const f = dalfoxPocToFinding({
      type: "V",
      inject_type: "inHTML-URL",
      data: "http://127.0.0.1:3000/rest/products/search?q=<svg/onload=alert(1)>",
      param: "q",
      payload: "<svg/onload=alert(1)>",
      evidence: "reflected in JSON body",
      cwe: "CWE-79",
      severity: "High",
    })!;
    expect(f).not.toBeNull();
    expect(f.severity).toBe("HIGH");
    expect(f.title).toContain('parameter "q"');
    expect(f.title).not.toContain('parameter ""');
    expect(f.endpoint).toContain("/rest/products/search");
    expect(f.evidence).toContain("payload:");
  });

  test("a no-parameter reflected hit WITH a url is low-confidence, titled by URL (not empty param)", () => {
    const f = dalfoxPocToFinding({
      type: "R",
      inject_type: "inHTML",
      data: "http://127.0.0.1:3000/rest/products/search?q=apple",
      param: "",
      payload: "<script>alert(1)</script>",
      evidence: "",
      severity: "High",
    })!;
    expect(f).not.toBeNull();
    expect(f.title).not.toContain('parameter ""');
    expect(f.title).toContain("http://127.0.0.1:3000/rest/products/search");
    expect(f.endpoint).toBe("http://127.0.0.1:3000/rest/products/search?q=apple");
    expect(f.severity).toBe("LOW"); // downgraded, unattributed
  });

  test("a completely empty PoC (no param, url, payload, evidence) is dropped", () => {
    expect(
      dalfoxPocToFinding({ type: "R", param: "", data: "", payload: "", evidence: "" }),
    ).toBeNull();
  });

  test("the exact empty artifact shape from the run does not become a parameter \"\" finding", () => {
    // dalfox emitted empty param + empty data for the JSON endpoint.
    const f = dalfoxPocToFinding({ type: "reflected", param: "", data: "", payload: "", evidence: "" });
    expect(f).toBeNull(); // nothing actionable -> not rendered as `parameter ""`
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
