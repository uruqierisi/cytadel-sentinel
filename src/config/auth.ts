import type { Scope } from "./schema.js";
import { logger } from "../lib/logger.js";

/**
 * Resolve authenticated-scanning session material.
 *
 * The scope YAML only names ENV VARS; secret values are read at runtime and
 * NEVER persisted or logged. For `cookie`/`header` the material is available
 * synchronously here; for `form_login` this returns a disabled placeholder that
 * config/authSession.ts fills in by actually logging in at pipeline start.
 *
 * REDACTION: `redactedHeaderLines` carries safe-to-log forms ("Cookie: ***") —
 * the raw `headerLines`/`headerMap`/`cookie` must never reach a log, audit,
 * report, or raw artifact.
 */

export type AuthMode = "none" | "cookie" | "header" | "form_login";

export interface ResolvedAuth {
  enabled: boolean;
  mode: AuthMode;
  /** All header lines incl. Cookie — for -H based tools (httpx/nuclei/katana). */
  headerLines: string[];
  /** Same, as a {name: value} map for the undici HTTP client. */
  headerMap: Record<string, string>;
  /** The cookie string (for tools with a native --cookie flag), else null. */
  cookie: string | null;
  /** Header lines EXCLUDING Cookie — for tools where the cookie goes via --cookie. */
  nonCookieHeaderLines: string[];
  /** Safe-to-log redacted header lines ("Name: ***"). */
  redactedHeaderLines: string[];
  /** True once an established session was lost and could not be recovered. */
  degraded: boolean;
}

export function emptyAuth(): ResolvedAuth {
  return {
    enabled: false,
    mode: "none",
    headerLines: [],
    headerMap: {},
    cookie: null,
    nonCookieHeaderLines: [],
    redactedHeaderLines: [],
    degraded: false,
  };
}

/** Redact a header line's VALUE, keeping the name: "Cookie: abc" -> "Cookie: ***". */
export function redactHeaderLine(line: string): string {
  const i = line.indexOf(":");
  if (i <= 0) return "***";
  return `${line.slice(0, i)}: ***`;
}

/** Build auth state from a raw cookie string. */
export function authFromCookie(cookie: string, mode: AuthMode = "cookie"): ResolvedAuth {
  return {
    enabled: true,
    mode,
    headerLines: [`Cookie: ${cookie}`],
    headerMap: { Cookie: cookie },
    cookie,
    nonCookieHeaderLines: [],
    redactedHeaderLines: ["Cookie: ***"],
    degraded: false,
  };
}

/** Build auth state from a single "Name: value" header line. */
export function authFromHeaderLine(line: string, mode: AuthMode = "header"): ResolvedAuth | null {
  const idx = line.indexOf(":");
  if (idx <= 0) return null;
  const name = line.slice(0, idx).trim();
  const val = line.slice(idx + 1).trim();
  if (!name || !val) return null;
  const isCookie = name.toLowerCase() === "cookie";
  return {
    enabled: true,
    mode,
    headerLines: [`${name}: ${val}`],
    headerMap: { [name]: val },
    cookie: isCookie ? val : null,
    nonCookieHeaderLines: isCookie ? [] : [`${name}: ${val}`],
    redactedHeaderLines: [`${name}: ***`],
    degraded: false,
  };
}

export function resolveAuth(scope: Scope): ResolvedAuth {
  const auth = scope.auth;

  if (auth.type === "none") return emptyAuth();

  // form_login is established asynchronously (network) at pipeline start; return
  // a disabled placeholder here so context construction stays synchronous.
  if (auth.type === "form_login") {
    return { ...emptyAuth(), mode: "form_login" };
  }

  if (!auth.session) return emptyAuth();
  const value = process.env[auth.session]?.trim();
  if (!value) {
    logger.warn(
      { envVar: auth.session, type: auth.type },
      "auth configured but session env var is empty — proceeding UNAUTHENTICATED",
    );
    return emptyAuth();
  }

  if (auth.type === "cookie") return authFromCookie(value);

  // type === "header": value is a full header line "Name: value".
  const built = authFromHeaderLine(value);
  if (!built) {
    logger.warn(
      { envVar: auth.session },
      'auth.type="header" but env value is not "Name: value" — ignoring',
    );
    return emptyAuth();
  }
  return built;
}
