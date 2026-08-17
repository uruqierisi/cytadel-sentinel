import type { Logger } from "pino";
import type { Scope } from "../config/schema.js";
import type { ResolvedAuth } from "../config/auth.js";
import type { LoadedScope } from "../config/scope.js";
import { resolveAuth } from "../config/auth.js";
import { evaluateScope, type ScopeDecision } from "../config/inScope.js";
import { audit } from "../lib/audit.js";
import { runLogger } from "../lib/logger.js";
import { ToolRegistry } from "../lib/toolResolver.js";
import { RunBus } from "./events.js";

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
  /** Lifecycle event bus the reporter subscribes to. Stages emit onto it. */
  bus: RunBus;
  /**
   * External tools resolved to absolute paths. Populated once at pipeline start
   * (executePipeline calls `tools.resolveAll`). Stage wrappers MUST spawn via
   * `tools.pathFor(name)` — never a bare tool name — so PATH order can never
   * decide which binary (e.g. Python vs ProjectDiscovery httpx) is used.
   */
  tools: ToolRegistry;
}

export function createRunContext(params: {
  runId: string;
  actor: string;
  loaded: LoadedScope;
  cliAllowDestructive: boolean;
  bus?: RunBus;
}): RunContext {
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
    log: runLogger(runId),
    bus: params.bus ?? new RunBus(),
    tools: new ToolRegistry(),
  };
}

/**
 * The single choke point stages call for every candidate target. Evaluates the
 * scope gate AND audit-logs the decision. Returns whether the target is allowed.
 *
 * Only rejections and first-time acceptances are audited at INFO; this keeps the
 * trail complete without a line per repeated in-scope URL.
 */
export async function gate(ctx: RunContext, target: string): Promise<ScopeDecision> {
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
export async function gateMany(ctx: RunContext, targets: string[]): Promise<string[]> {
  const allowed: string[] = [];
  for (const t of targets) {
    const decision = await gate(ctx, t);
    if (decision.allowed) allowed.push(t);
  }
  return allowed;
}
