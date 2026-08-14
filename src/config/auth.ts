import type { Scope } from "./schema.js";
import { logger } from "../lib/logger.js";

/**
 * Resolve authenticated-scanning session material.
 *
 * The scope YAML only names an ENV VAR; the secret value is read here at
 * runtime and never persisted or logged. Output is a list of raw header lines
 * ("Name: value") that scanners (nuclei/httpx) inject via their -H flag and the
 * verification HTTP client sends as headers — so testing goes past login.
 */

export interface ResolvedAuth {
  enabled: boolean;
  /** Header lines to inject, e.g. ["Cookie: session=abc"] or ["Authorization: Bearer x"]. */
  headerLines: string[];
  /** Same, as a {name: value} map for the undici HTTP client. */
  headerMap: Record<string, string>;
}

const EMPTY: ResolvedAuth = { enabled: false, headerLines: [], headerMap: {} };

export function resolveAuth(scope: Scope): ResolvedAuth {
  const auth = scope.auth;
  if (auth.type === "none" || !auth.session) return EMPTY;

  const value = process.env[auth.session]?.trim();
  if (!value) {
    logger.warn(
      { envVar: auth.session, type: auth.type },
      "auth configured but session env var is empty — proceeding UNAUTHENTICATED",
    );
    return EMPTY;
  }

  if (auth.type === "cookie") {
    const line = `Cookie: ${value}`;
    return { enabled: true, headerLines: [line], headerMap: { Cookie: value } };
  }

  // type === "header": value is a full header line "Name: value".
  const idx = value.indexOf(":");
  if (idx <= 0) {
    logger.warn(
      { envVar: auth.session },
      'auth.type="header" but env value is not "Name: value" — ignoring',
    );
    return EMPTY;
  }
  const name = value.slice(0, idx).trim();
  const val = value.slice(idx + 1).trim();
  return { enabled: true, headerLines: [`${name}: ${val}`], headerMap: { [name]: val } };
}
