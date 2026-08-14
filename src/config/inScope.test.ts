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
