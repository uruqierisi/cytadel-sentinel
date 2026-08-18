import { describe, test, expect, vi } from "vitest";
vi.mock("../../lib/audit.js", () => ({ audit: vi.fn() }));
import { extractEndpointCandidates, analyzeJsAssets } from "./jsAnalyze.js";
import { ScopeSchema } from "../../config/schema.js";
import { resolveAuth } from "../../config/auth.js";
import type { RunContext } from "../../core/context.js";
import type { HttpResponse } from "../../lib/http.js";

const BASE = "http://127.0.0.1:3000/main-es2015.js";

describe("extractEndpointCandidates — SPA bundle static analysis (WP2)", () => {
  test("finds fetch(\"/rest/products/search?q=\") as an in-scope injection candidate", () => {
    const js = `
      function searchProducts(q){
        return fetch("/rest/products/search?q=" + encodeURIComponent(q)).then(r=>r.json());
      }
    `;
    const urls = extractEndpointCandidates(js, BASE);
    // Resolved against the bundle origin, empty value filled so it's a working request.
    expect(urls).toContain("http://127.0.0.1:3000/rest/products/search?q=1");
  });

  test("extracts axios / XHR / config-object endpoints with query params", () => {
    const js = `
      axios.get("/api/users?role=admin");
      const xhr = new XMLHttpRequest(); xhr.open("POST", "/api/orders?draft=true");
      const cfg = { url: "/rest/basket?id=1" };
    `;
    const urls = extractEndpointCandidates(js, BASE);
    expect(urls).toEqual(
      expect.arrayContaining([
        "http://127.0.0.1:3000/api/users?role=admin",
        "http://127.0.0.1:3000/api/orders?draft=true",
        "http://127.0.0.1:3000/rest/basket?id=1",
      ]),
    );
  });

  test("ignores param-less endpoints (not injectable) and non-http", () => {
    const js = `fetch("/rest/products"); fetch("mailto:x@y.z?subject=hi"); fetch("/health");`;
    const urls = extractEndpointCandidates(js, BASE);
    expect(urls.every((u) => u.startsWith("http://127.0.0.1:3000"))).toBe(true);
    expect(urls.some((u) => u.includes("/rest/products?"))).toBe(false); // no query => dropped
  });

  test("absolute external URLs are extracted verbatim (gating happens later)", () => {
    const js = `fetch("https://evil.example.com/api?x=1")`;
    const urls = extractEndpointCandidates(js, BASE);
    // extraction keeps it; the scope gate rejects it in analyzeJsAssets.
    expect(urls).toContain("https://evil.example.com/api?x=1");
  });
});

describe("analyzeJsAssets — every extracted URL passes through gate()", () => {
  const noopLog = { info() {}, warn() {}, error() {}, debug() {}, child() { return noopLog; } } as unknown as RunContext["log"];

  function ctxFor(): RunContext {
    const scope = ScopeSchema.parse({
      name: "js", authorized_by: "me", authorization_ref: "L",
      in_scope: { domains: ["127.0.0.1"] },
    });
    return { runId: "r", actor: "t", scopeHash: "h", scope, auth: resolveAuth(scope), log: noopLog } as unknown as RunContext;
  }

  const res = (body: string): HttpResponse => ({
    status: 200, headers: {}, body, truncated: false, durationMs: 1, requestLine: "GET",
  });

  test("in-scope endpoint kept, out-of-scope endpoint rejected by the gate", async () => {
    const js = `
      fetch("/rest/products/search?q=apple");         // in scope
      fetch("https://evil.example.com/steal?token=1"); // out of scope
    `;
    const http = vi.fn(async () => res(js));
    const cands = await analyzeJsAssets(ctxFor(), ["http://127.0.0.1:3000/main.js"], http);

    const urls = cands.map((c) => c.url);
    expect(urls).toContain("http://127.0.0.1:3000/rest/products/search?q=apple");
    expect(urls.some((u) => u.includes("evil.example.com"))).toBe(false); // gated out
    for (const c of cands) {
      expect(c.method).toBe("GET");
      expect(c.source).toBe("js");
    }
  });
});
