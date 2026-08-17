import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, test, expect } from "vitest";
import { parseSqlmapStdout } from "./sqlmap.js";

// Use globalThis.URL: the `URL` const below shadows the URL constructor name.
const fixture = (name: string): string =>
  readFileSync(fileURLToPath(new globalThis.URL(`./__fixtures__/${name}`, import.meta.url)), "utf8");

const URL = "http://testasp.vulnweb.com/showforum.asp?id=0";

const SQLMAP_OUTPUT = `
[*] starting @ 12:00:00
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=0 AND 1234=1234

    Type: error-based
    Title: Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause
    Payload: id=0 AND 5678=CONVERT(INT,...)
---
[*] shutting down @ 12:03:00
`;

describe("parseSqlmapStdout", () => {
  test("extracts a confirmed injection point with its types", () => {
    const findings = parseSqlmapStdout(SQLMAP_OUTPUT, URL);
    expect(findings.length).toBe(1);
    const f = findings[0]!;
    expect(f.sourceTool).toBe("sqlmap");
    expect(f.severity).toBe("HIGH");
    expect(f.cwe).toBe(89);
    expect(f.endpoint).toBe(URL);
    expect(f.title).toContain('parameter "id"');
    expect(f.evidence).toContain("boolean-based blind");
  });

  test("returns nothing when sqlmap finds no injection", () => {
    const out = "all tested parameters do not appear to be injectable.";
    expect(parseSqlmapStdout(out, URL)).toEqual([]);
  });

  test("handles two injectable parameters", () => {
    const out = `
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind
---
Parameter: cat (GET)
    Type: time-based blind
    Title: time-based blind
---
`;
    const findings = parseSqlmapStdout(out, URL);
    expect(findings.length).toBe(2);
    expect(findings.map((f) => f.title).join(" ")).toContain("cat");
  });

  test("partial capture: sqlmap killed mid-block (no closing ---) still yields the injection point", () => {
    // Real truncated sqlmap output: the second Type/Title is confirmed but the
    // final Payload line was cut and there is no closing '---'. The end-of-input
    // flush must still emit the parameter finding.
    const content = fixture("sqlmap-truncated.log");
    const findings = parseSqlmapStdout(content, URL);
    expect(findings.length).toBe(1);
    const f = findings[0]!;
    expect(f.sourceTool).toBe("sqlmap");
    expect(f.severity).toBe("HIGH");
    expect(f.cwe).toBe(89);
    expect(f.title).toContain('parameter "id"');
    // Both confirmed types landed before the cut.
    expect(f.evidence).toContain("boolean-based blind");
    expect(f.evidence).toContain("error-based");
  });
});
