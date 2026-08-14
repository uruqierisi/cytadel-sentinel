import type { Logger } from "pino";
import type { Scope } from "../config/schema.js";
import type { ResolvedAuth } from "../config/auth.js";
import type { LoadedScope } from "../config/scope.js";
import { type ScopeDecision } from "../config/inScope.js";
/**
 * Per-run context threaded through every stage. Bundles the validated scope,
 * the scope gate, resolved auth, and effective destructive setting so no stage
 * has to re-derive them (or forget to check them).
 */
export interface RunContext {
    runId: string;
    actor: string;
    scope: Scope;
    scopeHash: string;
    scopeSourcePath: string;
    auth: ResolvedAuth;
    /** Effective: scope.allow_destructive AND the --allow-destructive CLI flag. */
    allowDestructive: boolean;
    log: Logger;
}
export declare function createRunContext(params: {
    runId: string;
    actor: string;
    loaded: LoadedScope;
    cliAllowDestructive: boolean;
}): RunContext;
/**
 * The single choke point stages call for every candidate target. Evaluates the
 * scope gate AND audit-logs the decision. Returns whether the target is allowed.
 *
 * Only rejections and first-time acceptances are audited at INFO; this keeps the
 * trail complete without a line per repeated in-scope URL.
 */
export declare function gate(ctx: RunContext, target: string): Promise<ScopeDecision>;
/**
 * Filter a list of candidate targets down to the in-scope ones, auditing each
 * decision. Use this at the boundary of every stage.
 */
export declare function gateMany(ctx: RunContext, targets: string[]): Promise<string[]>;
