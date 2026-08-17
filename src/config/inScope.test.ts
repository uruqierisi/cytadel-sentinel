import { describe, test, expect } from "vitest";
import { ScopeSchema } from "./schema.js";
import { evaluateScope, isInScope } from "./inScope.js";

const scope = ScopeSchema.parse({
  name: "acme-web",
  authorized_by: "security@company",
  authorization_ref: "TICKET-123",
  in_scope: {
    domains: ["app.acme.com", "*.acme.com"],
    urls: ["https://app.acme.com"],
  },
  exclusions: {
    domains: ["status.acme.com"],
    paths: ["/logout", "/delete"],
  },
  auth: { type: "none" },
  rate_limit_rps: 10,
  allow_destructive: false,
});

describe("scope gate — inclusions", () => {
  test("explicit in-scope domain is allowed", () => {
    expect(isInScope(scope, "app.acme.com")).toBe(true);
  });

  test("wildcard matches a subdomain", () => {
    const d = evaluateScope(scope, "api.acme.com");
    expect(d.allowed).toBe(true);
    expect(d.reason).toBe("matched-wildcard");
  });

  test("wildcard does NOT match the apex", () => {
    // "*.acme.com" must not match bare "acme.com".
    expect(isInScope(scope, "acme.com")).toBe(false);
  });

  test("full URL target resolves by host", () => {
    expect(isInScope(scope, "https://app.acme.com/dashboard")).toBe(true);
  });

  test("host:port target resolves by host", () => {
    expect(isInScope(scope, "api.acme.com:8443")).toBe(true);
  });
});

describe("scope gate — exclusions win", () => {
  test("excluded domain is rejected even though it matches the wildcard", () => {
    const d = evaluateScope(scope, "status.acme.com");
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe("excluded-domain");
  });

  test("excluded path prefix is rejected", () => {
    const d = evaluateScope(scope, "https://app.acme.com/logout");
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe("excluded-path");
  });

  test("excluded path prefix rejects deeper paths", () => {
    expect(isInScope(scope, "https://app.acme.com/delete/user/42")).toBe(false);
  });
});

describe("scope gate — rejections", () => {
  test("out-of-scope domain is rejected", () => {
    const d = evaluateScope(scope, "evil.example.com");
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe("no-match");
  });

  test("unparseable target is rejected", () => {
    const d = evaluateScope(scope, "!!!not a host!!!");
    expect(d.allowed).toBe(false);
  });

  test("case is normalized", () => {
    expect(isInScope(scope, "API.ACME.COM")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Local lab testing: "localhost" and bare IPv4 (e.g. Juice Shop on
// 127.0.0.1:3000) must validate AND match through the scope gate.
// ---------------------------------------------------------------------------
describe("scope validation — local lab hosts", () => {
  const parseWith = (domains: string[]) =>
    ScopeSchema.safeParse({
      name: "local-lab",
      authorized_by: "me",
      authorization_ref: "LOCAL",
      in_scope: { domains },
    });

  test("accepts localhost", () => {
    expect(parseWith(["localhost"]).success).toBe(true);
  });

  test("accepts bare IPv4 addresses", () => {
    for (const ip of ["127.0.0.1", "10.0.0.5", "192.168.1.20"]) {
      expect(parseWith([ip]).success).toBe(true);
    }
  });

  test("still accepts FQDNs and wildcards", () => {
    expect(parseWith(["example.com", "*.example.com"]).success).toBe(true);
  });

  test("rejects an out-of-range IPv4 octet", () => {
    expect(parseWith(["256.0.0.1"]).success).toBe(false);
  });

  test("rejects garbage", () => {
    expect(parseWith(["not a host"]).success).toBe(false);
  });
});

describe("scope gate — local lab hosts", () => {
  const lab = ScopeSchema.parse({
    name: "juice-shop",
    authorized_by: "me",
    authorization_ref: "LOCAL",
    in_scope: { domains: ["localhost", "127.0.0.1"] },
  });

  test("http://127.0.0.1:3000/... matches in_scope 127.0.0.1 (port ignored)", () => {
    const d = evaluateScope(lab, "http://127.0.0.1:3000/#/login");
    expect(d.allowed).toBe(true);
    expect(d.host).toBe("127.0.0.1");
    expect(d.reason).toBe("matched-domain");
  });

  test("http://localhost:3000 matches in_scope localhost", () => {
    const d = evaluateScope(lab, "http://localhost:3000");
    expect(d.allowed).toBe(true);
    expect(d.host).toBe("localhost");
  });

  test("bare host:port form also matches (host compared, not port)", () => {
    expect(isInScope(lab, "127.0.0.1:3000")).toBe(true);
    expect(isInScope(lab, "localhost:3000/rest/products")).toBe(true);
  });

  test("a different local IP is still rejected", () => {
    expect(isInScope(lab, "http://192.168.1.50:3000")).toBe(false);
  });
});
