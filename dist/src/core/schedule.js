/**
 * Phase 2 — scheduled weekly runs + verification layer. SCAFFOLD ONLY.
 *
 * Design intent (do NOT enable in Phase 1):
 *   - A cron trigger (node-cron or a system cron/systemd timer calling
 *     `sentinel run <scope>`) enqueues a run weekly per registered scope.
 *   - After the report stage, run the verification stage (stages/verify) to
 *     confirm AUTO findings and route MANUAL ones to a review queue.
 *
 * Everything below is intentionally inert. Wiring it is Phase-2 work.
 */
// TODO(Phase 2): load these from config (e.g. scope/schedule.yaml).
export const SCHEDULED_SCOPES = [];
/**
 * TODO(Phase 2): register cron jobs that enqueue runs for each ScheduledScope.
 * Implementation sketch:
 *   import cron from "node-cron";
 *   for (const s of SCHEDULED_SCOPES)
 *     cron.schedule(s.cron, async () => {
 *       const { jobData } = await createRun({ scopeFile: s.scopeFile, actor: s.actor, allowDestructive: false });
 *       await enqueueRunJob(jobData);
 *     });
 */
export function startScheduler() {
    throw new Error("Phase 2 not implemented: scheduled runs are a scaffold only");
}
/**
 * TODO(Phase 2): call runVerify(ctx) from executePipeline AFTER the report
 * stage (or as its own queued follow-up job) once the AUTO verifiers in
 * stages/verify/verifiers.ts are complete.
 */
export async function runVerificationLayer(_ctx) {
    throw new Error("Phase 2 not implemented: verification layer wiring is a scaffold only");
}
//# sourceMappingURL=schedule.js.map