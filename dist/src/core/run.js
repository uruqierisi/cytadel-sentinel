import { prisma } from "../db/client.js";
import { audit, currentActor } from "../lib/audit.js";
import { loadScope } from "../config/scope.js";
import { createRunContext } from "./context.js";
import { evaluateScope } from "../config/inScope.js";
/**
 * Create a Run row from a scope file. Validates + loads the scope, records who
 * triggered it and the scope hash, and performs the mandatory up-front scope
 * sanity check: at least one seed target must resolve in-scope, otherwise the
 * run is REJECTED before any network activity.
 */
export async function createRun(params) {
    const actor = params.actor ?? currentActor();
    const loaded = await loadScope(params.scopeFile);
    await audit({
        actor,
        action: "SCOPE_LOAD",
        scopeHash: loaded.scopeHash,
        detail: { scope: loaded.scope.name, source: loaded.sourcePath },
    });
    // Hard pre-check: at least one in_scope seed must actually pass the gate.
    const seeds = [
        ...loaded.scope.in_scope.urls,
        ...loaded.scope.in_scope.domains.map((d) => (d.startsWith("*.") ? "host." + d.slice(2) : d)),
    ];
    const anyInScope = seeds.some((s) => evaluateScope(loaded.scope, s).allowed);
    if (!anyInScope) {
        await audit({
            actor,
            action: "SCOPE_REJECT",
            scopeHash: loaded.scopeHash,
            detail: { reason: "no in_scope target survives exclusions" },
        });
        throw new Error("scope rejected: every in_scope target is excluded — nothing to test");
    }
    const run = await prisma.run.create({
        data: {
            status: "QUEUED",
            triggeredBy: actor,
            scopeName: loaded.scope.name,
            scopeHash: loaded.scopeHash,
            authorizedBy: loaded.scope.authorized_by,
            authorizationRef: loaded.scope.authorization_ref,
            allowDestructive: loaded.scope.allow_destructive && params.allowDestructive,
        },
    });
    return {
        runId: run.id,
        jobData: { runId: run.id, scopeFile: loaded.sourcePath, actor, allowDestructive: params.allowDestructive },
    };
}
/** Rebuild the RunContext for a queued job, verifying the scope hasn't drifted. */
export async function contextForJob(data) {
    const loaded = await loadScope(data.scopeFile);
    const run = await prisma.run.findUniqueOrThrow({ where: { id: data.runId } });
    if (run.scopeHash !== loaded.scopeHash) {
        throw new Error(`scope file changed since the run was queued (hash ${run.scopeHash.slice(0, 12)} != ${loaded.scopeHash.slice(0, 12)}) — refusing to run`);
    }
    return createRunContext({
        runId: data.runId,
        actor: data.actor,
        loaded,
        cliAllowDestructive: data.allowDestructive,
    });
}
//# sourceMappingURL=run.js.map