import type { Scope } from "./schema.js";
/**
 * The scope gate.
 *
 * NON-NEGOTIABLE RULE: nothing runs against any host not explicitly in scope.
 * Every stage MUST route every candidate target through isInScope() BEFORE any
 * network request. Exclusions ALWAYS win over inclusions.
 *
 * A target may be a bare hostname, "host:port", or a full URL. The decision is
 * returned with a machine-readable reason so the caller can audit-log it.
 */
export type ScopeReason = "excluded-domain" | "excluded-path" | "matched-url" | "matched-domain" | "matched-wildcard" | "no-match" | "unparseable";
export interface ScopeDecision {
    allowed: boolean;
    target: string;
    /** The normalized host we evaluated (lowercased, no port). */
    host: string | null;
    /** The path we evaluated (for URL targets), else null. */
    path: string | null;
    reason: ScopeReason;
}
/**
 * Evaluate a target against the scope. Pure and synchronous — cheap to call on
 * every discovered asset.
 */
export declare function evaluateScope(scope: Scope, target: string): ScopeDecision;
/** Boolean convenience wrapper. Prefer evaluateScope() when you need the reason. */
export declare function isInScope(scope: Scope, target: string): boolean;
