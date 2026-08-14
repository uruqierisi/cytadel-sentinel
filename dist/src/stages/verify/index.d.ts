import { type RunContext } from "../../core/context.js";
/**
 * Verification stage (Phase 2 — SCAFFOLD).
 *
 * The classifier and the reference verifier are implemented; this orchestrator
 * shows the intended flow and persists verification status. It is NOT yet wired
 * into the Phase-1 pipeline (executePipeline) — enable it in Phase 2 after the
 * remaining AUTO verifiers land.
 *
 * Flow per finding:
 *   classify -> AUTO: re-gate target, replay via a matching Verifier (lib/http),
 *               VERIFIED / LOW_CONFIDENCE + evidence.
 *            -> MANUAL: mark MANUAL_REVIEW (review queue), never auto-touch.
 *            -> NEVER_AUTO: destructive; leave untouched.
 */
export interface VerifyResult {
    verified: number;
    lowConfidence: number;
    manual: number;
    neverAuto: number;
}
export declare function runVerify(ctx: RunContext): Promise<VerifyResult>;
