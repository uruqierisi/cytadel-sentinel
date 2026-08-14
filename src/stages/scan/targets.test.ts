import { describe, test, expect } from "vitest";
import { buildNucleiTargets } from "./targets.js";
import { mergeJsonlLines } from "../../lib/parse.js";

describe("buildNucleiTargets — reduce nuclei input (fix 1)", () => {
  const base = ["http://testasp.vulnweb.com"];

  test("collapses query-param variants to one unique path", () => {
    const endpoints = [
      "http://testasp.vulnweb.com/showforum.asp?id=0",
      "http://testasp.vulnweb.com/showforum.asp?id=1",
      "http://testasp.vulnweb.com/showforum.asp?id=2",
      "http://testasp.vulnweb.com/showthread.asp?id=9",
    ];
    const targets = buildNucleiTargets(base, endpoints, 150);
    // origin + 2 unique paths (showforum.asp, showthread.asp) — NOT 4 param URLs.
    expect(targets).toContain("http://testasp.vulnweb.com/");
    expect(targets).toContain("http://testasp.vulnweb.com/showforum.asp");
    expect(targets).toContain("http://testasp.vulnweb.com/showthread.asp");
    expect(targets.length).toBe(3);
  });

  test("host roots come first and survive the cap", () => {
    const endpoints = Array.from({ length: 500 }, (_, i) => `http://testasp.vulnweb.com/p${i}.asp?x=${i}`);
    const targets = buildNucleiTargets(base, endpoints, 10);
    expect(targets.length).toBe(10);
    expect(targets[0]).toBe("http://testasp.vulnweb.com/");
  });

  test("dedupes and tolerates scheme-less input", () => {
    const targets = buildNucleiTargets(
      ["testasp.vulnweb.com", "http://testasp.vulnweb.com"],
      ["testasp.vulnweb.com/a", "testasp.vulnweb.com/a?z=1"],
      150,
    );
    // both base forms -> one https origin + one http origin? scheme-less defaults https.
    const paths = targets.filter((t) => t.endsWith("/a"));
    expect(paths.length).toBe(1);
  });
});

describe("mergeJsonlLines — keep ALL emitted lines (fix 2)", () => {
  test("merges flushed file + stdout tail, deduped", () => {
    // Simulates SIGTERM: file had only 1 flushed line; stdout captured 3.
    const file = '{"template-id":"waf-detect","info":{"name":"WAF"}}';
    const stdout = [
      '{"template-id":"waf-detect","info":{"name":"WAF"}}',
      '{"template-id":"tech-detect","info":{"name":"Tech"}}',
      '{"template-id":"microsoft-iis-version","info":{"name":"IIS"}}',
    ].join("\n");

    const merged = mergeJsonlLines([file, stdout]);
    const lines = merged.split("\n");
    expect(lines.length).toBe(3); // union, deduped — nothing lost
    expect(merged).toContain("waf-detect");
    expect(merged).toContain("tech-detect");
    expect(merged).toContain("microsoft-iis-version");
  });

  test("drops a truncated tail line and blank lines", () => {
    const stdout = '{"a":1}\n{"b":2}\n{"c":';
    const merged = mergeJsonlLines(["", stdout]);
    expect(merged.split("\n").length).toBe(2);
  });

  test("empty everywhere yields empty string", () => {
    expect(mergeJsonlLines(["", "  \n \n"])).toBe("");
  });
});
