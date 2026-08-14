import { type RunContext } from "./context.js";
/**
 * Run lifecycle helpers: create the Run row from a validated scope, and rebuild
 * a RunContext when a queued job is processed.
 */
export interface RunJobData {
    runId: string;
    scopeFile: string;
    actor: string;
    allowDestructive: boolean;
}
/**
 * Create a Run row from a scope file. Validates + loads the scope, records who
 * triggered it and the scope hash, and performs the mandatory up-front scope
 * sanity check: at least one seed target must resolve in-scope, otherwise the
 * run is REJECTED before any network activity.
 */
export declare function createRun(params: {
    scopeFile: string;
    actor?: string;
    allowDestructive: boolean;
}): Promise<{
    runId: string;
    jobData: RunJobData;
}>;
/** Rebuild the RunContext for a queued job, verifying the scope hasn't drifted. */
export declare function contextForJob(data: RunJobData): Promise<RunContext>;
