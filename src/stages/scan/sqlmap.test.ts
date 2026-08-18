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

describe("parseSqlmapStdout — one finding per confirmed injection point", () => {
  test("one param with two Type blocks => two findings (per-technique)", () => {
    const findings = parseSqlmapStdout(SQLMAP_OUTPUT, URL);
    expect(findings.length).toBe(2);
    for (const f of findings) {
      expect(f.sourceTool).toBe("sqlmap");
      expect(f.severity).toBe("HIGH");
      expect(f.cwe).toBe(89);
      expect(f.endpoint).toBe(URL);
      expect(f.title).toContain('parameter "id"');
    }
    const titles = findings.map((f) => f.title).join(" | ");
    expect(titles).toContain("boolean-based blind");
    expect(titles).toContain("error-based");
    // Each carries its own payload.
    expect(findings[0]!.evidence).toContain("payload: id=0 AND 1234=1234");
    expect(findings[1]!.evidence).toContain("payload: id=0 AND 5678=CONVERT(INT,...)");
    // Distinct dedupe ids per technique.
    expect(findings[0]!.uniqueId).not.toBe(findings[1]!.uniqueId);
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
    expect(findings.map((f) => f.title).join(" ")).toContain('parameter "id"');
  });

  test("REAL captured Juice Shop stdout (?q=apple) => 2 High findings, param q, SQLite, payloads", () => {
    // The full, real sqlmap stdout (preamble + injection block + back-end DBMS).
    const out = fixture("sqlmap-qapple.stdout.log");
    const url = "http://127.0.0.1:3000/rest/products/search?q=apple";
    const findings = parseSqlmapStdout(out, url);
    expect(findings.length).toBe(2);
    for (const f of findings) {
      expect(f.severity).toBe("HIGH");
      expect(f.endpoint).toBe(url); // the q=apple URL
      expect(f.title).toContain('parameter "q"');
      expect(f.evidence).toContain("q=apple"); // real payload value
      expect(f.evidence).toContain("DBMS: SQLite");
      expect(f.description).toContain("SQLite");
      expect(f.description).toContain('parameter "q"');
    }
    expect(findings[0]!.title).toContain("boolean-based blind");
    expect(findings[1]!.title).toContain("time-based blind");
    expect(findings[0]!.uniqueId).not.toBe(findings[1]!.uniqueId);
  });

  test("partial capture: sqlmap killed mid-block (no closing ---) still yields the points", () => {
    // Real truncated sqlmap output: two Type blocks confirmed but the final
    // Payload line was cut and there is no closing '---'. The end-of-input flush
    // must still emit BOTH injection points.
    const content = fixture("sqlmap-truncated.log");
    const findings = parseSqlmapStdout(content, URL);
    expect(findings.length).toBe(2);
    for (const f of findings) {
      expect(f.sourceTool).toBe("sqlmap");
      expect(f.severity).toBe("HIGH");
      expect(f.cwe).toBe(89);
      expect(f.title).toContain('parameter "id"');
    }
    const titles = findings.map((f) => f.title).join(" | ");
    expect(titles).toContain("boolean-based blind");
    expect(titles).toContain("error-based");
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

  test("non-cookie headers are appended via -H", () => {
    const args = buildSqlmapArgs([], SIGNATURES[0]!, CFG, "/out", {
      headerLines: ["X-Api-Key: abc"],
    });
    expect(args).toContain("-H");
    expect(args[args.indexOf("-H") + 1]).toBe("X-Api-Key: abc");
  });

  test("a session cookie is injected via sqlmap's native --cookie (not -H)", () => {
    const args = buildSqlmapArgs([], SIGNATURES[0]!, CFG, "/out", { cookie: "token=abc; sid=xyz" });
    expect(args).toContain("--cookie");
    expect(args[args.indexOf("--cookie") + 1]).toBe("token=abc; sid=xyz");
    expect(args).not.toContain("-H"); // cookie must NOT double as a -H header
  });

  test("every invocation flushes the session (fresh test, no stale false-negative cache)", () => {
    const plan = planSqlmapInvocations([], SIGNATURES, CFG, BASE_OUT);
    for (const p of plan) {
      expect(p.args).toContain("--flush-session");
    }
  });

  test("does NOT use --smart (it skips blind-injectable params that fail the basic heuristic)", () => {
    const plan = planSqlmapInvocations([], SIGNATURES, CFG, BASE_OUT);
    for (const p of plan) {
      expect(p.args).not.toContain("--smart");
      // The full-testing flags are still present.
      expect(p.args).toContain("--flush-session");
      expect(p.args).toContain("--level=2");
      expect(p.args).toContain("--risk=2");
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
