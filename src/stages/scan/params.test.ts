import { describe, test, expect } from "vitest";
import { paramSignature, dedupeParamSignatures, planInjectionTargets } from "./params.js";
import { ScopeSchema } from "../../config/schema.js";
import { isInScope } from "../../config/inScope.js";

describe("paramSignature — ignore values, key on path + param names", () => {
  test("same path + param name, different values => same signature", () => {
    const a = paramSignature("http://testasp.vulnweb.com/showforum.asp?id=1");
    const b = paramSignature("http://testasp.vulnweb.com/showforum.asp?id=2");
    expect(a).toBe(b);
  });

  test("different param name => different signature", () => {
    const a = paramSignature("http://testasp.vulnweb.com/showforum.asp?id=1");
    const b = paramSignature("http://testasp.vulnweb.com/showforum.asp?cat=1");
    expect(a).not.toBe(b);
  });

  test("param order does not matter", () => {
    const a = paramSignature("http://h.com/p?a=1&b=2");
    const b = paramSignature("http://h.com/p?b=9&a=8");
    expect(a).toBe(b);
  });

  test("no-param URL has no signature", () => {
    expect(paramSignature("http://testasp.vulnweb.com/Default.asp")).toBeNull();
  });
});

describe("dedupeParamSignatures — collapse the 183 (fix 2/4)", () => {
  test("collapses many value-variants to one representative per signature", () => {
    const urls: string[] = [];
    for (let i = 0; i < 100; i++) urls.push(`http://testasp.vulnweb.com/showforum.asp?id=${i}`);
    for (let i = 0; i < 83; i++) urls.push(`http://testasp.vulnweb.com/showthread.asp?id=${i}`);

    const deduped = dedupeParamSignatures(urls, 25);
    // 183 URLs -> 2 distinct signatures.
    expect(deduped.length).toBe(2);
    // Representatives carry real values so the tool has a working request.
    expect(deduped.some((u) => /showforum\.asp\?id=/.test(u))).toBe(true);
    expect(deduped.some((u) => /showthread\.asp\?id=/.test(u))).toBe(true);
  });

  test("keeps the known SQLi target and honors the cap", () => {
    const urls = Array.from({ length: 200 }, (_, i) => `http://testasp.vulnweb.com/p${i}.asp?q=${i}`);
    urls.unshift("http://testasp.vulnweb.com/showforum.asp?id=1");
    const deduped = dedupeParamSignatures(urls, 25);
    expect(deduped.length).toBe(25);
    expect(deduped[0]).toBe("http://testasp.vulnweb.com/showforum.asp?id=1");
  });

  test("183 real-shaped param URLs collapse to a few signatures that INCLUDE Search.asp?tfSearch", () => {
    // The exact regression: recon handed dalfox 183 param URLs dominated by
    // duplicate id= values. Deduped, dalfox must still reach the tfSearch XSS.
    const urls: string[] = [];
    for (let i = 0; i < 120; i++) urls.push(`http://testasp.vulnweb.com/showforum.asp?id=${i}`);
    for (let i = 0; i < 60; i++) urls.push(`http://testasp.vulnweb.com/showthread.asp?id=${i}&pg=1`);
    urls.push("http://testasp.vulnweb.com/Search.asp?tfSearch=test");
    urls.push("http://testasp.vulnweb.com/Search.asp?tfSearch=other"); // same signature
    expect(urls.length).toBe(182); // 120 + 60 + 2 — the ~183 raw shape

    const deduped = dedupeParamSignatures(urls, 25);
    // Collapses to 3 distinct signatures (showforum, showthread, Search).
    expect(deduped.length).toBe(3);
    // The tfSearch target survives the collapse and is a single representative.
    const search = deduped.filter((u) => /Search\.asp\?tfSearch=/.test(u));
    expect(search.length).toBe(1);
  });

  test("drops param-less URLs entirely", () => {
    const deduped = dedupeParamSignatures(
      ["http://testasp.vulnweb.com/Default.asp", "http://testasp.vulnweb.com/x.asp?a=1"],
      25,
    );
    expect(deduped).toEqual(["http://testasp.vulnweb.com/x.asp?a=1"]);
  });
});

describe("planInjectionTargets — seed_param_urls reach the scanners with REAL values", () => {
  const SEARCH_SIG = "http://127.0.0.1:3000/rest/products/search?q";
  const SEARCH_SEED = "http://127.0.0.1:3000/rest/products/search?q=apple";

  // Mirror the scan orchestrator: raw seeds are scope-gated (values PRESERVED),
  // merged with discovery, then deduped by signature.
  function injectionTargetsFor(scopeInput: unknown, discovered: string[] = []): string[] {
    const scope = ScopeSchema.parse(scopeInput);
    const gatedSeeds = scope.seed_param_urls.filter((u) => isInScope(scope, u));
    return planInjectionTargets(gatedSeeds, discovered, 25).targets;
  }

  const juiceShopScope = {
    name: "juice-shop",
    authorized_by: "me",
    authorization_ref: "LOCAL",
    in_scope: { domains: ["127.0.0.1"] },
    allow_destructive: true,
    seed_param_urls: [SEARCH_SEED],
  };

  test("a seeded ?q=apple reaches the scanners as q=apple, NOT q=1", () => {
    const targets = injectionTargetsFor(juiceShopScope);
    // The exact seed value is preserved for the sqlmap/dalfox request.
    expect(targets).toContain(SEARCH_SEED);
    expect(targets.some((u) => u.includes("q=apple"))).toBe(true);
    expect(targets.some((u) => /\?q=1$/.test(u))).toBe(false);
    // Dedupe signature still collapses variants on this endpoint.
    expect(targets.map((u) => paramSignature(u))).toContain(SEARCH_SIG);
  });

  test("two seed value-variants collapse by signature, keeping the first real value", () => {
    const targets = injectionTargetsFor({
      ...juiceShopScope,
      seed_param_urls: [SEARCH_SEED, "http://127.0.0.1:3000/rest/products/search?q=banana"],
    });
    expect(targets).toEqual([SEARCH_SEED]); // first real value wins, one signature
  });

  test("seeds survive the cap even behind lots of discovered params (seeds go first)", () => {
    const discovered = Array.from({ length: 100 }, (_, i) => `http://127.0.0.1:3000/p${i}.asp?x=${i}`);
    const { targets, fromSeeds, fromDiscovery } = planInjectionTargets([SEARCH_SEED], discovered, 25);
    expect(targets.length).toBe(25);
    expect(fromSeeds).toBe(1);
    expect(fromDiscovery).toBe(24);
    expect(targets[0]).toBe(SEARCH_SEED); // seed first, real value intact
  });

  test("an out-of-scope seed is gated out and does not appear", () => {
    const targets = injectionTargetsFor({
      ...juiceShopScope,
      seed_param_urls: ["http://evil.example.com/rest/products/search?q=apple"],
    });
    expect(targets.length).toBe(0);
  });
});
