import type { Logger } from "pino";
import { httpRequest, type HttpResponse } from "../lib/http.js";
import { audit } from "../lib/audit.js";
import { redactHeaderLine, type ResolvedAuth } from "./auth.js";
import type { Scope, ScopeAuth } from "./schema.js";
import type { RunContext } from "../core/context.js";

/**
 * form_login session establishment + liveness (WP1).
 *
 * All secret values come from ENV (username/password env var names in scope);
 * they are never logged or audited — only redacted header lines are recorded.
 * The HTTP client is arg-safe (structured method/url/headers/body; no shell).
 *
 * The `httpFn` seam lets tests inject a fake transport.
 */

export type HttpFn = (url: string, opts?: Parameters<typeof httpRequest>[1]) => Promise<HttpResponse>;

interface SessionMaterial {
  cookie: string | null;
  bearer: string | null;
  headerLines: string[];
  headerMap: Record<string, string>;
}

/** Parse Set-Cookie header(s) into a single "a=b; c=d" Cookie string. */
export function parseSetCookies(raw: string | string[] | undefined): string | null {
  if (!raw) return null;
  const list = Array.isArray(raw) ? raw : [raw];
  const pairs: string[] = [];
  for (const entry of list) {
    // Keep only "name=value", dropping attributes (Path=, HttpOnly, ...).
    const first = entry.split(";")[0]?.trim();
    if (first && first.includes("=")) pairs.push(first);
  }
  return pairs.length ? pairs.join("; ") : null;
}

/**
 * Split a pointer into tokens. Supports RFC 6901 JSON Pointer ("/a/b", leading
 * slash, `~1`->`/`, `~0`->`~`) AND legacy dot-notation ("a.b").
 */
export function pointerTokens(pointer: string): string[] {
  if (pointer.startsWith("/")) {
    return pointer
      .split("/")
      .slice(1)
      .map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
  }
  return pointer.split(".");
}

/**
 * Resolve a token/cookie value from a JSON body via a pointer. Accepts RFC 6901
 * ("/authentication/token", as Juice Shop uses) or dot-notation
 * ("authentication.token"). Returns the string value, or null if the body isn't
 * JSON or the pointer doesn't resolve to a non-empty string.
 */
export function extractJsonPointer(body: string, pointer: string): string | null {
  let cur: unknown;
  try {
    cur = JSON.parse(body);
  } catch {
    return null;
  }
  for (const key of pointerTokens(pointer)) {
    if (cur && typeof cur === "object" && key in (cur as Record<string, unknown>)) {
      cur = (cur as Record<string, unknown>)[key];
    } else {
      return null;
    }
  }
  return typeof cur === "string" && cur.length > 0 ? cur : null;
}

/** Apply captured session material onto a live ResolvedAuth (in place). */
export function applySession(auth: ResolvedAuth, m: SessionMaterial): void {
  auth.enabled = true;
  auth.degraded = false;
  auth.headerLines = m.headerLines;
  auth.headerMap = m.headerMap;
  auth.cookie = m.cookie;
  auth.nonCookieHeaderLines = m.headerLines.filter((l) => !/^cookie:/i.test(l));
  auth.redactedHeaderLines = m.headerLines.map(redactHeaderLine);
}

/** Perform the form/API login and capture cookie(s) and/or a bearer token. */
export async function performFormLogin(
  a: ScopeAuth,
  httpFn: HttpFn,
  log: Logger,
): Promise<SessionMaterial | null> {
  const user = a.username ? process.env[a.username]?.trim() : undefined;
  const pass = a.password ? process.env[a.password]?.trim() : undefined;
  if (!user || !pass) {
    log.warn(
      { userEnv: a.username, passEnv: a.password },
      "auth: form_login username/password env var empty — cannot log in",
    );
    return null;
  }
  if (!a.login_url || !a.username_field || !a.password_field) return null;

  let body: string;
  let contentType: string;
  if (a.content_type === "json") {
    body = JSON.stringify({ [a.username_field]: user, [a.password_field]: pass });
    contentType = "application/json";
  } else {
    body = new URLSearchParams({ [a.username_field]: user, [a.password_field]: pass }).toString();
    contentType = "application/x-www-form-urlencoded";
  }

  let res: HttpResponse;
  try {
    res = await httpFn(a.login_url, {
      method: "POST",
      headers: { "content-type": contentType },
      body,
      maxRedirections: 0,
    });
  } catch (err) {
    log.error({ err, loginUrl: a.login_url }, "auth: form_login request failed");
    return null;
  }

  const cookie = parseSetCookies(res.headers["set-cookie"] as string | string[] | undefined);
  let bearer: string | null = null;
  if (a.token_json_pointer) {
    let jsonParsed = true;
    try {
      JSON.parse(res.body);
    } catch {
      jsonParsed = false;
    }
    bearer = extractJsonPointer(res.body, a.token_json_pointer);
    // Redacted diagnostics: never the token value — only whether it resolved.
    log.info(
      {
        status: res.status,
        jsonParsed,
        pointer: a.token_json_pointer,
        tokenFound: bearer !== null,
        tokenLength: bearer?.length ?? 0,
      },
      "auth: form_login token extraction",
    );
  }
  if (!cookie && !bearer) {
    log.warn({ status: res.status, cookieFound: Boolean(cookie) }, "auth: form_login yielded no cookie or token");
    return null;
  }

  const headerLines: string[] = [];
  const headerMap: Record<string, string> = {};
  if (cookie) {
    headerLines.push(`Cookie: ${cookie}`);
    headerMap.Cookie = cookie;
  }
  if (bearer) {
    headerLines.push(`Authorization: Bearer ${bearer}`);
    headerMap.Authorization = `Bearer ${bearer}`;
  }
  return { cookie, bearer, headerLines, headerMap };
}

export interface LivenessConfig {
  /** Explicit success status (auth.success_status). Highest priority. */
  status?: number;
  /** Body substring (or legacy 3-digit status) that means logged-in. */
  indicator?: string;
}

/**
 * Decide whether an authenticated probe response indicates a live session, for
 * the explicit modes. Priority: success_status, then success_indicator (body
 * substring or 3-digit status), then DEFAULT (2xx and not 401/403). The default
 * mode's anonymous cross-check lives in probeSession (it needs a second request).
 */
export function isSessionLive(res: HttpResponse, cfg: LivenessConfig = {}): boolean {
  if (cfg.status !== undefined) return res.status === cfg.status;
  if (cfg.indicator) {
    if (/^\d{3}$/.test(cfg.indicator)) return res.status === Number(cfg.indicator);
    return res.body.includes(cfg.indicator);
  }
  // Default: a 2xx that is not an auth failure. (401/403/3xx handled as false.)
  return res.status >= 200 && res.status < 300;
}

/**
 * Probe an authenticated URL for liveness. Explicit status/indicator modes are
 * deterministic. In DEFAULT mode we also fire an ANONYMOUS request and compare:
 * if the two differ meaningfully (anon 401/403, or a different status/body), the
 * session is confirmed working; if they're identical the check URL doesn't
 * reflect auth (poor choice) — we warn but don't false-degrade a 2xx.
 */
async function probeSession(
  url: string,
  auth: ResolvedAuth,
  cfg: LivenessConfig,
  httpFn: HttpFn,
  log: Logger,
): Promise<boolean> {
  let authed: HttpResponse;
  try {
    authed = await httpFn(url, { headers: auth.headerMap, maxRedirections: 0 });
  } catch (err) {
    log.warn({ err, url }, "auth: session liveness probe failed");
    return false;
  }

  // Explicit modes: deterministic, no anonymous comparison needed.
  if (cfg.status !== undefined || cfg.indicator) return isSessionLive(authed, cfg);

  // DEFAULT mode: 401/403/non-2xx (incl. redirect-to-login) => lost.
  if (authed.status === 401 || authed.status === 403) return false;
  if (!(authed.status >= 200 && authed.status < 300)) return false;

  // authed is 2xx — cross-check against an anonymous request to validate that
  // this URL actually reflects authentication (best-effort, never fatal).
  try {
    const anon = await httpFn(url, { maxRedirections: 0 });
    const differs =
      anon.status === 401 ||
      anon.status === 403 ||
      anon.status !== authed.status ||
      anon.body !== authed.body;
    if (differs) {
      log.info(
        { url, authedStatus: authed.status, anonStatus: anon.status },
        "auth: session-check confirmed (auth changes the response)",
      );
    } else {
      log.warn(
        { url },
        "auth: session-check URL returns the SAME response with/without auth — choose an endpoint that returns 401/403 when unauthenticated",
      );
    }
  } catch {
    // Anonymous cross-check is a diagnostic; its failure never degrades a 2xx.
  }
  return true;
}

/** Build the liveness config from the scope auth block. */
function livenessConfig(a: ScopeAuth): LivenessConfig {
  return { status: a.success_status, indicator: a.success_indicator };
}

/**
 * Establish the session at pipeline start. cookie/header are already resolved
 * (resolveAuth); this only performs form_login. Failure degrades to anonymous
 * (loud, audited) rather than throwing.
 */
export async function establishAuth(ctx: RunContext, httpFn: HttpFn = httpRequest): Promise<void> {
  const a = ctx.scope.auth;
  if (a.type !== "form_login") return;

  const material = await performFormLogin(a, httpFn, ctx.log);
  if (!material) {
    ctx.auth.degraded = true;
    ctx.log.warn("auth: form_login failed — scanning UNAUTHENTICATED (coverage degraded)");
    await audit({
      runId: ctx.runId,
      actor: ctx.actor,
      action: "AUTH_SESSION_LOST",
      scopeHash: ctx.scopeHash,
      detail: { phase: "establish", reason: "login failed", mode: "form_login" },
    });
    return;
  }
  applySession(ctx.auth, material);
  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "AUTH_ESTABLISHED",
    scopeHash: ctx.scopeHash,
    detail: { mode: "form_login", headers: ctx.auth.redactedHeaderLines },
  });
  ctx.log.info({ headers: ctx.auth.redactedHeaderLines }, "auth: session established");
}

/**
 * Verify the session is still live; on loss, attempt ONE re-login (form_login).
 * If still lost, mark the run's auth coverage degraded (audited). Returns true
 * if authenticated coverage is intact.
 */
export async function ensureSessionLive(ctx: RunContext, httpFn: HttpFn = httpRequest): Promise<boolean> {
  if (!ctx.auth.enabled) return true; // nothing to keep alive
  const a = ctx.scope.auth;
  const checkUrl = sessionCheckUrl(a, ctx.scope);
  if (!checkUrl) return true; // no URL to probe — cannot check, don't false-alarm
  const cfg = livenessConfig(a);

  if (await probeSession(checkUrl, ctx.auth, cfg, httpFn, ctx.log)) return true;

  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "AUTH_SESSION_LOST",
    scopeHash: ctx.scopeHash,
    detail: { phase: "liveness", checkUrl },
  });
  ctx.log.warn({ checkUrl }, "auth: session appears lost mid-run");

  if (a.type === "form_login") {
    const material = await performFormLogin(a, httpFn, ctx.log);
    if (material) {
      applySession(ctx.auth, material);
      if (await probeSession(checkUrl, ctx.auth, cfg, httpFn, ctx.log)) {
        await audit({
          runId: ctx.runId,
          actor: ctx.actor,
          action: "AUTH_REESTABLISHED",
          scopeHash: ctx.scopeHash,
          detail: { checkUrl, headers: ctx.auth.redactedHeaderLines },
        });
        ctx.log.info("auth: session re-established after loss");
        return true;
      }
    }
  }

  ctx.auth.degraded = true;
  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "AUTH_DEGRADED",
    scopeHash: ctx.scopeHash,
    detail: { note: "authenticated coverage degraded — continued as anonymous", checkUrl },
  });
  ctx.log.warn("auth: coverage DEGRADED — remaining requests are unauthenticated");
  return false;
}

function sessionCheckUrl(a: ScopeAuth, scope: Scope): string | null {
  return a.session_check_url ?? a.login_url ?? scope.in_scope.urls[0] ?? null;
}
