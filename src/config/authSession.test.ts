import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";
import type { HttpResponse } from "../lib/http.js";
import type { RunContext } from "../core/context.js";

// Capture audit events without touching the DB / JSONL sidecar.
const { auditMock } = vi.hoisted(() => ({ auditMock: vi.fn() }));
vi.mock("../lib/audit.js", () => ({ audit: (...a: unknown[]) => auditMock(...a) }));

import {
  parseSetCookies,
  extractJsonPointer,
  pointerTokens,
  isSessionLive,
  performFormLogin,
  establishAuth,
  ensureSessionLive,
} from "./authSession.js";
import { resolveAuth } from "./auth.js";
import { ScopeSchema } from "./schema.js";

const SECRET_COOKIE = "sid=SECRETSESSIONVALUE123";
const SECRET_TOKEN = "SECRETBEARERTOKEN456";
const USER = "admin@juice.sh";
const PASS = "SuperSecretPassw0rd";

function res(partial: Partial<HttpResponse>): HttpResponse {
  return {
    status: 200,
    headers: {},
    body: "",
    truncated: false,
    durationMs: 1,
    requestLine: "GET x",
    ...partial,
  };
}

const noopLog = { info() {}, warn() {}, error() {}, debug() {}, child() { return noopLog; } } as unknown as RunContext["log"];

function makeCtx(scopeInput: unknown): RunContext {
  const scope = ScopeSchema.parse(scopeInput);
  return {
    runId: "run-1",
    actor: "tester",
    scopeHash: "hash",
    scope,
    auth: resolveAuth(scope),
    log: noopLog,
  } as unknown as RunContext;
}

const formLoginScope = {
  name: "juice-shop",
  authorized_by: "me",
  authorization_ref: "LOCAL",
  in_scope: { domains: ["127.0.0.1"], urls: ["http://127.0.0.1:3000/profile"] },
  auth: {
    type: "form_login",
    login_url: "http://127.0.0.1:3000/rest/user/login",
    username_field: "email",
    password_field: "password",
    username: "SENTINEL_TEST_USER",
    password: "SENTINEL_TEST_PASS",
    content_type: "json",
    token_json_pointer: "/authentication/token", // RFC 6901 (Juice Shop)
    // No success_indicator: use DEFAULT liveness (2xx + anon cross-check).
    session_check_url: "http://127.0.0.1:3000/rest/user/whoami",
  },
};

beforeEach(() => {
  auditMock.mockReset();
  process.env.SENTINEL_TEST_USER = USER;
  process.env.SENTINEL_TEST_PASS = PASS;
});
afterEach(() => {
  delete process.env.SENTINEL_TEST_USER;
  delete process.env.SENTINEL_TEST_PASS;
});

describe("schema — form_login validation", () => {
  test("accepts a complete form_login block", () => {
    expect(ScopeSchema.safeParse(formLoginScope).success).toBe(true);
  });

  test("rejects form_login missing required fields", () => {
    const bad = { ...formLoginScope, auth: { type: "form_login", login_url: "http://127.0.0.1:3000/login" } };
    expect(ScopeSchema.safeParse(bad).success).toBe(false);
  });

  test("secret VALUES are never in the scope — only env var names", () => {
    const parsed = ScopeSchema.parse(formLoginScope);
    // username/password hold ENV VAR NAMES, not the credentials.
    expect(parsed.auth.username).toBe("SENTINEL_TEST_USER");
    expect(parsed.auth.password).toBe("SENTINEL_TEST_PASS");
    expect(JSON.stringify(parsed)).not.toContain(USER);
    expect(JSON.stringify(parsed)).not.toContain(PASS);
  });
});

describe("pure helpers", () => {
  test("parseSetCookies keeps name=value, drops attributes, joins multiple", () => {
    expect(parseSetCookies("token=abc; Path=/; HttpOnly")).toBe("token=abc");
    expect(parseSetCookies(["a=1; Path=/", "b=2; Secure"])).toBe("a=1; b=2");
    expect(parseSetCookies(undefined)).toBeNull();
  });

  test("extractJsonPointer resolves RFC 6901 (/a/b) AND dot-notation (a.b)", () => {
    // The exact Juice Shop login body + pointer from the bug report.
    const juice = '{"authentication":{"token":"eyJ.EXACTTOKEN.sig"}}';
    expect(extractJsonPointer(juice, "/authentication/token")).toBe("eyJ.EXACTTOKEN.sig");

    const body = JSON.stringify({ authentication: { token: SECRET_TOKEN } });
    expect(extractJsonPointer(body, "/authentication/token")).toBe(SECRET_TOKEN); // slash form
    expect(extractJsonPointer(body, "authentication.token")).toBe(SECRET_TOKEN); // dot form
    expect(extractJsonPointer(body, "/authentication/missing")).toBeNull();
    expect(extractJsonPointer("not json", "/a/b")).toBeNull();
  });

  test("pointerTokens handles ~1/~0 escaping and both notations", () => {
    expect(pointerTokens("/a/b")).toEqual(["a", "b"]);
    expect(pointerTokens("/a~1b/c")).toEqual(["a/b", "c"]); // ~1 -> /
    expect(pointerTokens("a.b")).toEqual(["a", "b"]);
  });

  test("isSessionLive default mode: 2xx live, 3xx/401/403 lost", () => {
    expect(isSessionLive(res({ status: 200 }))).toBe(true);
    expect(isSessionLive(res({ status: 302 }))).toBe(false);
    expect(isSessionLive(res({ status: 401 }))).toBe(false);
    expect(isSessionLive(res({ status: 403 }))).toBe(false);
  });

  test("isSessionLive explicit status mode (success_status)", () => {
    expect(isSessionLive(res({ status: 200 }), { status: 200 })).toBe(true);
    expect(isSessionLive(res({ status: 204 }), { status: 200 })).toBe(false);
    // {"user":{}} at 200 is 'live' under status mode — no body string required.
    expect(isSessionLive(res({ status: 200, body: '{"user":{}}' }), { status: 200 })).toBe(true);
  });

  test("isSessionLive body-indicator mode (and legacy 3-digit status)", () => {
    expect(isSessionLive(res({ status: 200, body: "Welcome back" }), { indicator: "Welcome back" })).toBe(true);
    expect(isSessionLive(res({ status: 200, body: "login please" }), { indicator: "Welcome back" })).toBe(false);
    expect(isSessionLive(res({ status: 403 }), { indicator: "200" })).toBe(false);
  });
});

describe("performFormLogin", () => {
  test("captures a bearer token from a JSON response (Juice Shop shape)", async () => {
    const http = vi.fn(async () => res({ status: 200, body: JSON.stringify({ authentication: { token: SECRET_TOKEN } }) }));
    const m = await performFormLogin(ScopeSchema.parse(formLoginScope).auth, http, noopLog);
    expect(m).not.toBeNull();
    expect(m!.bearer).toBe(SECRET_TOKEN);
    expect(m!.headerLines).toContain(`Authorization: Bearer ${SECRET_TOKEN}`);
    // The login body carried the env-sourced credentials (never hardcoded).
    const sentBody = (http.mock.calls[0]![1] as { body: string }).body;
    expect(sentBody).toContain(USER);
  });

  test("captures a session cookie from Set-Cookie (form encoding)", async () => {
    const http = vi.fn(async () => res({ status: 200, headers: { "set-cookie": `${SECRET_COOKIE}; Path=/; HttpOnly` } }));
    const scope = ScopeSchema.parse({ ...formLoginScope, auth: { ...formLoginScope.auth, content_type: "form", token_json_pointer: undefined } });
    const m = await performFormLogin(scope.auth, http, noopLog);
    expect(m!.cookie).toBe(SECRET_COOKIE);
    expect(m!.headerLines).toContain(`Cookie: ${SECRET_COOKIE}`);
  });

  test("returns null when credentials env vars are empty", async () => {
    delete process.env.SENTINEL_TEST_PASS;
    const http = vi.fn(async () => res({}));
    expect(await performFormLogin(ScopeSchema.parse(formLoginScope).auth, http, noopLog)).toBeNull();
    expect(http).not.toHaveBeenCalled();
  });
});

describe("establishAuth — login and inject", () => {
  test("form_login establishes a session and audits AUTH_ESTABLISHED (redacted)", async () => {
    const http = vi.fn(async () => res({ status: 200, body: JSON.stringify({ authentication: { token: SECRET_TOKEN } }) }));
    const ctx = makeCtx(formLoginScope);
    await establishAuth(ctx, http);

    expect(ctx.auth.enabled).toBe(true);
    expect(ctx.auth.headerMap.Authorization).toBe(`Bearer ${SECRET_TOKEN}`);
    expect(ctx.auth.nonCookieHeaderLines).toContain(`Authorization: Bearer ${SECRET_TOKEN}`);
    expect(ctx.auth.redactedHeaderLines).toEqual(["Authorization: ***"]);

    const actions = auditMock.mock.calls.map((c) => (c[0] as { action: string }).action);
    expect(actions).toContain("AUTH_ESTABLISHED");
  });

  test("Juice Shop end-to-end: token -> Bearer -> whoami {\"user\":{}} 200/401 -> stays established", async () => {
    const ctx = makeCtx(formLoginScope);
    const http = vi.fn(async (url: string, opts?: { method?: string; headers?: Record<string, string> }) => {
      if (opts?.method === "POST") {
        return res({ status: 200, body: JSON.stringify({ authentication: { token: SECRET_TOKEN } }) });
      }
      // The Juice Shop quirk: whoami returns {"user":{}} 200 WITH the Bearer, 401 without.
      const authed = opts?.headers?.Authorization === `Bearer ${SECRET_TOKEN}`;
      return authed ? res({ status: 200, body: '{"user":{}}' }) : res({ status: 401, body: "unauthorized" });
    });

    await establishAuth(ctx, http);
    expect(ctx.auth.enabled).toBe(true);
    expect(ctx.auth.headerMap.Authorization).toBe(`Bearer ${SECRET_TOKEN}`);

    // DEFAULT liveness: authed 200 + anon 401 differ => confirmed, NOT degraded.
    const live = await ensureSessionLive(ctx, http);
    expect(live).toBe(true);
    expect(ctx.auth.degraded).toBe(false);

    const actions = auditMock.mock.calls.map((c) => (c[0] as { action: string }).action);
    expect(actions).toContain("AUTH_ESTABLISHED");
    expect(actions).not.toContain("AUTH_SESSION_LOST"); // no false loss
    expect(actions).not.toContain("AUTH_DEGRADED");
  });

  test("default liveness stays alive when check URL 401s anonymously and 200s with token", async () => {
    const ctx = makeCtx(formLoginScope);
    ctx.auth.enabled = true;
    ctx.auth.headerMap = { Authorization: `Bearer ${SECRET_TOKEN}` };
    const http = vi.fn(async (_url: string, opts?: { headers?: Record<string, string> }) =>
      opts?.headers?.Authorization ? res({ status: 200, body: '{"user":{}}' }) : res({ status: 401 }),
    );
    expect(await ensureSessionLive(ctx, http)).toBe(true);
    expect(ctx.auth.degraded).toBe(false);
    const actions = auditMock.mock.calls.map((c) => (c[0] as { action: string }).action);
    expect(actions).not.toContain("AUTH_SESSION_LOST");
  });

  test("default liveness: a poor check URL (200 with AND without auth) stays alive but warns", async () => {
    const ctx = makeCtx(formLoginScope);
    ctx.auth.enabled = true;
    ctx.auth.headerMap = { Authorization: `Bearer ${SECRET_TOKEN}` };
    // Same 200 body regardless of auth (the whoami-is-a-poor-choice case).
    const http = vi.fn(async () => res({ status: 200, body: '{"user":{}}' }));
    expect(await ensureSessionLive(ctx, http)).toBe(true); // not falsely degraded
    expect(ctx.auth.degraded).toBe(false);
  });

  test("failed login degrades to anonymous and audits AUTH_SESSION_LOST", async () => {
    const http = vi.fn(async () => res({ status: 401, body: "invalid" }));
    const ctx = makeCtx(formLoginScope);
    await establishAuth(ctx, http);

    expect(ctx.auth.enabled).toBe(false);
    expect(ctx.auth.degraded).toBe(true);
    const actions = auditMock.mock.calls.map((c) => (c[0] as { action: string }).action);
    expect(actions).toContain("AUTH_SESSION_LOST");
  });
});

describe("ensureSessionLive — mid-run loss + re-login", () => {
  test("session lost mid-run triggers a re-login and AUTH_REESTABLISHED", async () => {
    const ctx = makeCtx(formLoginScope);
    // Seed an already-established session.
    ctx.auth.enabled = true;
    ctx.auth.headerMap = { Authorization: "Bearer OLD" };
    ctx.auth.nonCookieHeaderLines = ["Authorization: Bearer OLD"];

    let call = 0;
    const http = vi.fn(async (_url: string, opts?: { method?: string }) => {
      call++;
      if (opts?.method === "POST") {
        // re-login succeeds with a fresh token
        return res({ status: 200, body: JSON.stringify({ authentication: { token: "FRESHTOKEN" } }) });
      }
      // first probe = lost (302), probe after re-login = live (200 + indicator)
      return call === 1 ? res({ status: 302 }) : res({ status: 200, body: "Welcome back" });
    });

    const ok = await ensureSessionLive(ctx, http);
    expect(ok).toBe(true);
    expect(ctx.auth.headerMap.Authorization).toBe("Bearer FRESHTOKEN");
    const actions = auditMock.mock.calls.map((c) => (c[0] as { action: string }).action);
    expect(actions).toContain("AUTH_SESSION_LOST");
    expect(actions).toContain("AUTH_REESTABLISHED");
  });

  test("re-login still failing marks coverage degraded (AUTH_DEGRADED)", async () => {
    const ctx = makeCtx(formLoginScope);
    ctx.auth.enabled = true;
    const http = vi.fn(async (_url: string, opts?: { method?: string }) =>
      opts?.method === "POST" ? res({ status: 401, body: "nope" }) : res({ status: 302 }),
    );

    const ok = await ensureSessionLive(ctx, http);
    expect(ok).toBe(false);
    expect(ctx.auth.degraded).toBe(true);
    const actions = auditMock.mock.calls.map((c) => (c[0] as { action: string }).action);
    expect(actions).toContain("AUTH_DEGRADED");
  });
});

describe("redaction — no secret reaches audit", () => {
  test("secret cookie/token/credential values never appear in audit events", async () => {
    const http = vi.fn(async () =>
      res({
        status: 200,
        headers: { "set-cookie": `${SECRET_COOKIE}; HttpOnly` },
        body: JSON.stringify({ authentication: { token: SECRET_TOKEN } }),
      }),
    );
    const ctx = makeCtx(formLoginScope);
    await establishAuth(ctx, http);

    const auditDump = JSON.stringify(auditMock.mock.calls);
    expect(auditDump).not.toContain("SECRETSESSIONVALUE123");
    expect(auditDump).not.toContain(SECRET_TOKEN);
    expect(auditDump).not.toContain(PASS);
    expect(auditDump).not.toContain(USER);
    // Redacted forms are what's recorded.
    expect(ctx.auth.redactedHeaderLines.join(" ")).not.toContain(SECRET_TOKEN);
    expect(ctx.auth.redactedHeaderLines.every((l) => l.endsWith("***"))).toBe(true);
  });
});
