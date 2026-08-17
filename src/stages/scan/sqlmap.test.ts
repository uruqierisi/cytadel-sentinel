import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, test, expect } from "vitest";
import {
  parseSqlmapStdout,
  planSqlmapInvocations,
  buildSqlmapArgs,
  sqlmapTargetOutDir,
  type SqlmapCfg,
} from "./sqlmap.js";

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

describe("planSqlmapInvocations — one isolated invocation per signature", () => {
  const CFG: SqlmapCfg = {
    level: 2,
    risk: 2,
    technique: "BEUST",
    threads: 4,
    requestTimeoutSec: 10,
    retries: 1,
  };
  const BASE_OUT = "/runs/abc/raw/sqlmap";
  const SIGNATURES = [
    "http://testasp.vulnweb.com/showforum.asp?id=1",
    "http://testasp.vulnweb.com/showthread.asp?id=1",
    "http://testasp.vulnweb.com/Search.asp?tfSearch=1",
    "http://testasp.vulnweb.com/Templatize.asp?item=1",
    "http://testasp.vulnweb.com/comment.asp?id=1",
  ];

  test("5 signatures => 5 invocations, one -u per URL", () => {
    const plan = planSqlmapInvocations([], SIGNATURES, CFG, BASE_OUT);
    expect(plan.length).toBe(5);

    // Each invocation targets exactly its own URL (nothing collapsed/dropped).
    const uOf = (args: string[]) => args[args.indexOf("-u") + 1];
    expect(plan.map((p) => uOf(p.args))).toEqual(SIGNATURES);

    // The real SQLi target IS among the executed targets.
    expect(plan.some((p) => uOf(p.args) === "http://testasp.vulnweb.com/showforum.asp?id=1")).toBe(true);
  });

  test("each invocation gets a DISTINCT output dir (no target.txt overwrite)", () => {
    const plan = planSqlmapInvocations([], SIGNATURES, CFG, BASE_OUT);
    const outDirs = plan.map((p) => p.outDir);
    expect(new Set(outDirs).size).toBe(5); // all distinct

    // And the --output-dir arg matches the invocation's dir, nested under base.
    for (const p of plan) {
      expect(path.dirname(p.outDir)).toBe(path.normalize(BASE_OUT));
      expect(p.args).toContain(`--output-dir=${p.outDir}`);
    }
  });

  test("level/risk/technique escalation flows into every invocation", () => {
    const plan = planSqlmapInvocations([], SIGNATURES, CFG, BASE_OUT);
    for (const p of plan) {
      expect(p.args).toContain("--level=2");
      expect(p.args).toContain("--risk=2");
      expect(p.args).toContain("--technique=BEUST");
    }
  });

  test("two different URLs never share an output dir", () => {
    const a = sqlmapTargetOutDir(BASE_OUT, "http://h/showforum.asp?id=1", 0);
    const b = sqlmapTargetOutDir(BASE_OUT, "http://h/showthread.asp?id=1", 1);
    expect(a).not.toBe(b);
  });

  test("headers are appended to each invocation", () => {
    const args = buildSqlmapArgs([], SIGNATURES[0]!, CFG, "/out", ["Cookie: a=b"]);
    expect(args).toContain("-H");
    expect(args[args.indexOf("-H") + 1]).toBe("Cookie: a=b");
  });

  test("every invocation flushes the session (fresh test, no stale false-negative cache)", () => {
    const plan = planSqlmapInvocations([], SIGNATURES, CFG, BASE_OUT);
    for (const p of plan) {
      expect(p.args).toContain("--flush-session");
    }
  });

  test("a seeded ?q=apple is fuzzed as q=apple (value preserved into -u), not q=1", () => {
    const seed = "http://127.0.0.1:3000/rest/products/search?q=apple";
    const args = buildSqlmapArgs([], seed, CFG, "/out");
    expect(args[args.indexOf("-u") + 1]).toBe(seed);
    expect(args.join(" ")).toContain("q=apple");
    expect(args.join(" ")).not.toContain("q=1");
  });
});

describe("parseSqlmapStdout — captures technique AND payload for the report", () => {
  const URL_APPLE = "http://127.0.0.1:3000/rest/products/search?q=apple";
  const OUT = `
sqlmap identified the following injection point(s):
---
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=apple') AND 1234=1234 AND ('abcd'='abcd

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: q=apple') AND 1234=RANDOMBLOB(100000000) AND ('a'='a
---
`;

  test("finding carries param, endpoint, technique and payload", () => {
    const findings = parseSqlmapStdout(OUT, URL_APPLE);
    expect(findings.length).toBe(1);
    const f = findings[0]!;
    expect(f.endpoint).toBe(URL_APPLE); // the q=apple URL, not q=1
    expect(f.title).toContain('parameter "q"');
    expect(f.severity).toBe("HIGH");
    expect(f.evidence).toContain("technique:");
    expect(f.evidence).toContain("boolean-based blind");
    expect(f.evidence).toContain("time-based blind");
    expect(f.evidence).toContain("payload:");
    expect(f.evidence).toContain("q=apple");
    expect(f.description).toContain("q=apple");
  });
});
