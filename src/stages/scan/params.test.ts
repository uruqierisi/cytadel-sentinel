import { describe, test, expect } from "vitest";
import { paramSignature, dedupeParamSignatures } from "./params.js";

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

  test("drops param-less URLs entirely", () => {
    const deduped = dedupeParamSignatures(
      ["http://testasp.vulnweb.com/Default.asp", "http://testasp.vulnweb.com/x.asp?a=1"],
      25,
    );
    expect(deduped).toEqual(["http://testasp.vulnweb.com/x.asp?a=1"]);
  });
});
