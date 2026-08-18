import { describe, test, expect } from "vitest";
import { candidateSignature, dedupeCandidates, countBySource, getCandidate, type InjectionCandidate } from "./candidates.js";

const cand = (o: Partial<InjectionCandidate>): InjectionCandidate => ({
  url: "http://h/x", method: "GET", body: null, contentType: null, paramNames: [], source: "discovery", ...o,
});

describe("candidate model (WP2)", () => {
  test("getCandidate derives GET param names from the query", () => {
    const c = getCandidate("http://127.0.0.1:3000/rest/products/search?q=apple", "seed");
    expect(c.method).toBe("GET");
    expect(c.paramNames).toEqual(["q"]);
    expect(c.source).toBe("seed");
  });

  test("signature ignores values but distinguishes method and body", () => {
    const a = getCandidate("http://h/s?q=apple", "seed");
    const b = getCandidate("http://h/s?q=banana", "discovery");
    expect(candidateSignature(a)).toBe(candidateSignature(b)); // same GET signature

    const post = cand({ url: "http://h/s", method: "POST", body: "q=x", paramNames: ["q"] });
    expect(candidateSignature(post)).not.toBe(candidateSignature(a)); // method + body differ
  });

  test("dedupeCandidates keeps first-seen per signature and caps", () => {
    const list = [
      getCandidate("http://h/s?q=apple", "seed"), // kept (seed value preserved)
      getCandidate("http://h/s?q=banana", "discovery"), // same signature -> dropped
      cand({ url: "http://h/s", method: "POST", body: "q=1", paramNames: ["q"] }),
    ];
    const out = dedupeCandidates(list, 25);
    expect(out.length).toBe(2);
    expect(out[0]!.url).toBe("http://h/s?q=apple");
    expect(out[0]!.source).toBe("seed");
  });

  test("cap is honoured (seeds first)", () => {
    const many = Array.from({ length: 50 }, (_, i) => getCandidate(`http://h/p${i}?x=1`, "discovery"));
    many.unshift(getCandidate("http://h/seed?z=1", "seed"));
    const out = dedupeCandidates(many, 10);
    expect(out.length).toBe(10);
    expect(out[0]!.source).toBe("seed");
  });

  test("countBySource attributes coverage", () => {
    const counts = countBySource([
      getCandidate("http://h/a?x=1", "js"),
      getCandidate("http://h/b?x=1", "js"),
      cand({ url: "http://h/g", method: "POST", body: "{}", source: "graphql", paramNames: ["id"] }),
    ]);
    expect(counts.js).toBe(2);
    expect(counts.graphql).toBe(1);
    expect(counts.openapi).toBe(0);
  });
});
