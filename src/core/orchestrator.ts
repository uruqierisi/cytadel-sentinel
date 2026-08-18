import { prisma } from "../db/client.js";
import { audit } from "../lib/audit.js";
import type { RunContext } from "./context.js";
import type { StageId } from "./events.js";
import { establishAuth, ensureSessionLive } from "../config/authSession.js";
import { runRecon } from "../stages/recon/index.js";
import { runScan } from "../stages/scan/index.js";
import { runNormalize } from "../stages/normalize/index.js";
import { runImport } from "../integrations/defectdojo/import.js";
import { runReport } from "../stages/report/index.js";

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

export async function executePipeline(ctx: RunContext): Promise<PipelineOutcome> {
  ctx.bus.runStart({
    toolName: "v1.0.0",
    runId: ctx.runId,
    scopeName: ctx.scope.name,
    authMode: ctx.auth.enabled ? ctx.scope.auth.type : "none",
    allowDestructive: ctx.allowDestructive,
  });

  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "RUN_START",
    scopeHash: ctx.scopeHash,
    detail: {
      scope: ctx.scope.name,
      authorizationRef: ctx.scope.authorization_ref,
      allowDestructive: ctx.allowDestructive,
    },
  });

  let current: StageId = "recon";
  try {
    // --- Resolve external tools to absolute paths BEFORE any stage runs. ---
    // This fails loudly if a required binary is present but the wrong build
    // (e.g. a Python `httpx` shadowing the ProjectDiscovery one) instead of
    // letting recon drift to a silent 0-result outcome.
    await ctx.tools.resolveAll(ctx.log);

    // --- Authenticated session ---
    // For form_login, log in and capture the session BEFORE recon so every tool
    // scans past login. A failure degrades to anonymous (loud + audited), never
    // a silent unauthenticated scan.
    await establishAuth(ctx);
    if (ctx.auth.enabled) {
      await ensureSessionLive(ctx);
      ctx.bus.stageProgress(
        "recon",
        ctx.auth.degraded ? "auth: session DEGRADED — scanning anonymously" : "auth: session active",
        false,
      );
    }
    // WP4 coverage: auth state + resolved tool versions.
    ctx.coverage.auth = {
      state: ctx.auth.degraded ? "degraded" : ctx.auth.enabled ? "authenticated" : "anonymous",
      mode: ctx.scope.auth.type,
    };
    ctx.coverage.tools = ctx.tools.list().map((t) => ({ name: t.name, version: t.version }));

    // --- Recon ---
    current = "recon";
    ctx.bus.stageStart("recon", "Recon");
    await prisma.run.update({ where: { id: ctx.runId }, data: { status: "RECON" } });
    const recon = await runRecon(ctx);
    ctx.bus.stageDone(
      "recon",
      `${recon.webTargets.length} web targets · ${recon.assetCount} assets · ${recon.jsUrls.length} JS`,
    );

    // --- Scan ---
    current = "scan";
    // Re-verify the session before the (longer) scan stage; re-login if it
    // dropped during recon.
    if (ctx.auth.enabled) await ensureSessionLive(ctx);
    ctx.bus.stageStart("scan", "Scan");
    await prisma.run.update({ where: { id: ctx.runId }, data: { status: "SCAN" } });
    const scan = await runScan(ctx, recon);
    ctx.bus.stageDone("scan", `${scan.artifacts.length} scan artifacts`);

    // --- Normalize ---
    current = "normalize";
    ctx.bus.stageStart("normalize", "Normalize");
    await prisma.run.update({ where: { id: ctx.runId }, data: { status: "NORMALIZE" } });
    const normalized = await runNormalize(ctx, scan);
    ctx.bus.stageDone("normalize", `${normalized.findings.length} unique findings`);

    // --- Import (DefectDojo) ---
    current = "import";
    ctx.bus.stageStart("import", "Import");
    await prisma.run.update({ where: { id: ctx.runId }, data: { status: "IMPORT" } });
    const imported = await runImport(ctx, scan);
    ctx.bus.stageDone("import", `engagement #${imported.engagementId} · ${imported.importedTests} imports`);

    // --- Report ---
    current = "report";
    ctx.bus.stageStart("report", "Report");
    await prisma.run.update({ where: { id: ctx.runId }, data: { status: "REPORT" } });
    const report = await runReport(ctx, imported.engagementId);
    ctx.bus.stageDone("report", "report ready");

    await prisma.run.update({
      where: { id: ctx.runId },
      data: { status: "COMPLETED", finishedAt: new Date() },
    });
    await audit({
      runId: ctx.runId,
      actor: ctx.actor,
      action: "RUN_COMPLETE",
      scopeHash: ctx.scopeHash,
      detail: { engagementId: imported.engagementId, report: report.htmlPath },
    });
    ctx.log.info({ report: report.htmlPath }, "pipeline: COMPLETED");

    ctx.bus.runDone({
      status: "COMPLETED",
      reportPath: report.htmlPath,
      engagementId: imported.engagementId,
      // Use the EXACT counts the report wrote to report.json so the CLI summary
      // and the report never diverge.
      severity: report.severityCounts,
    });
    return {
      runId: ctx.runId,
      status: "COMPLETED",
      reportHtmlPath: report.htmlPath,
      engagementId: imported.engagementId,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await prisma.run.update({
      where: { id: ctx.runId },
      data: { status: "FAILED", error: message, finishedAt: new Date() },
    });
    await audit({
      runId: ctx.runId,
      actor: ctx.actor,
      action: "RUN_FAILED",
      scopeHash: ctx.scopeHash,
      detail: { error: message, stage: current },
    });
    ctx.log.error({ err, stage: current }, "pipeline: FAILED");
    ctx.bus.stageFail(current, message);
    ctx.bus.runDone({ status: "FAILED", error: message });
    return { runId: ctx.runId, status: "FAILED", error: message };
  }
}
