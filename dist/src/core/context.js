import { resolveAuth } from "../config/auth.js";
import { evaluateScope } from "../config/inScope.js";
import { audit } from "../lib/audit.js";
import { runLogger } from "../lib/logger.js";
import { ToolRegistry } from "../lib/toolResolver.js";
import { newCoverage } from "./coverage.js";
import { RunBus } from "./events.js";
export function createRunContext(params) {
    const { runId, actor, loaded, cliAllowDestructive } = params;
    return {
        runId,
        actor,
        scope: loaded.scope,
        scopeHash: loaded.scopeHash,
        scopeSourcePath: loaded.sourcePath,
        auth: resolveAuth(loaded.scope),
        // BOTH gates must be true for destructive checks to be permitted.
        allowDestructive: loaded.scope.allow_destructive && cliAllowDestructive,
        confirmProduction: params.confirmProduction ?? false,
        log: runLogger(runId),
        bus: params.bus ?? new RunBus(),
        tools: new ToolRegistry(),
        coverage: newCoverage(),
    };
}
/**
 * The single choke point stages call for every candidate target. Evaluates the
 * scope gate AND audit-logs the decision. Returns whether the target is allowed.
 *
 * Only rejections and first-time acceptances are audited at INFO; this keeps the
 * trail complete without a line per repeated in-scope URL.
 */
export async function gate(ctx, target) {
    const decision = evaluateScope(ctx.scope, target);
    await audit({
        runId: ctx.runId,
        actor: ctx.actor,
        action: decision.allowed ? "SCOPE_ACCEPT" : "SCOPE_REJECT",
        scopeHash: ctx.scopeHash,
        target,
        detail: { host: decision.host, path: decision.path, reason: decision.reason },
    });
    if (!decision.allowed) {
        ctx.log.warn({ target, reason: decision.reason }, "scope gate REJECTED target");
    }
    return decision;
}
/**
 * Filter a list of candidate targets down to the in-scope ones, auditing each
 * decision. Use this at the boundary of every stage.
 */
export async function gateMany(ctx, targets) {
    const allowed = [];
    for (const t of targets) {
        const decision = await gate(ctx, t);
        if (decision.allowed)
            allowed.push(t);
    }
    return allowed;
}
//# sourceMappingURL=context.js.map