import type { RunContext } from "./context.js";
/**
 * The pipeline. Runs the Phase-1 stages in order, updating Run.status and
 * emitting lifecycle events onto ctx.bus (which the terminal reporter renders).
 * Any stage error fails the run cleanly (status FAILED, error recorded,
 * stage:fail + run:done emitted) — nothing is left half-done silently.
 *
 * Order: recon -> scan -> normalize -> import(DefectDojo) -> report.
 * (verify is Phase 2; scheduled/CI are Phases 2/3 — see stubs.)
 */
export interface PipelineOutcome {
    runId: string;
    status: "COMPLETED" | "FAILED";
    reportHtmlPath?: string;
    engagementId?: number;
    error?: string;
}
export declare function executePipeline(ctx: RunContext): Promise<PipelineOutcome>;
