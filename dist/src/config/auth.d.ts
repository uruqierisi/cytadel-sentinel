import type { Scope } from "./schema.js";
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
export declare function resolveAuth(scope: Scope): ResolvedAuth;
