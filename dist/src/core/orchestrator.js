import { prisma } from "../db/client.js";
import { audit } from "../lib/audit.js";
import { runRecon } from "../stages/recon/index.js";
import { runScan } from "../stages/scan/index.js";
import { runNormalize } from "../stages/normalize/index.js";
import { runImport } from "../integrations/defectdojo/import.js";
import { runReport } from "../stages/report/index.js";
export async function executePipeline(ctx) {
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
    try {
        await prisma.run.update({ where: { id: ctx.runId }, data: { status: "RECON" } });
        const recon = await runRecon(ctx);
        await prisma.run.update({ where: { id: ctx.runId }, data: { status: "SCAN" } });
        const scan = await runScan(ctx, recon);
        await prisma.run.update({ where: { id: ctx.runId }, data: { status: "NORMALIZE" } });
        await runNormalize(ctx, scan);
        await prisma.run.update({ where: { id: ctx.runId }, data: { status: "IMPORT" } });
        const imported = await runImport(ctx, scan);
        await prisma.run.update({ where: { id: ctx.runId }, data: { status: "REPORT" } });
        const report = await runReport(ctx, imported.engagementId);
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
        return {
            runId: ctx.runId,
            status: "COMPLETED",
            reportHtmlPath: report.htmlPath,
            engagementId: imported.engagementId,
        };
    }
    catch (err) {
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
            detail: { error: message },
        });
        ctx.log.error({ err }, "pipeline: FAILED");
        return { runId: ctx.runId, status: "FAILED", error: message };
    }
}
//# sourceMappingURL=orchestrator.js.map