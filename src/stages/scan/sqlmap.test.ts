import { describe, test, expect } from "vitest";
import { parseSqlmapStdout } from "./sqlmap.js";

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
});
