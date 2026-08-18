import type { Scope } from "./schema.js";
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
export declare function emptyAuth(): ResolvedAuth;
/** Redact a header line's VALUE, keeping the name: "Cookie: abc" -> "Cookie: ***". */
export declare function redactHeaderLine(line: string): string;
/** Build auth state from a raw cookie string. */
export declare function authFromCookie(cookie: string, mode?: AuthMode): ResolvedAuth;
/** Build auth state from a single "Name: value" header line. */
export declare function authFromHeaderLine(line: string, mode?: AuthMode): ResolvedAuth | null;
export declare function resolveAuth(scope: Scope): ResolvedAuth;
