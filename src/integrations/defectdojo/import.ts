import { prisma } from "../../db/client.js";
import { audit } from "../../lib/audit.js";
import type { RunContext } from "../../core/context.js";
import type { ScanResult } from "../../stages/scan/index.js";
import { DefectDojoClient } from "./client.js";

/**
 * Import stage: push every native scan artifact into DefectDojo via its
 * import-scan endpoint (built-in per-tool parsers), then record the engagement
 * on the Run. DefectDojo owns storage/dedupe/triage from here.
 */
export interface ImportResult {
  productId: number;
  engagementId: number;
  importedTests: number;
}

function ymd(date: Date): string {
  return date.toISOString().slice(0, 10);
}

export async function runImport(ctx: RunContext, scan: ScanResult): Promise<ImportResult> {
  ctx.log.info({ artifacts: scan.artifacts.length }, "import: starting");
  await audit({ runId: ctx.runId, actor: ctx.actor, action: "STAGE_START", detail: { stage: "import" } });

  const dojo = DefectDojoClient.fromEnv();
  if (!(await dojo.ping())) {
    throw new Error("DefectDojo is unreachable or the API key is invalid — check DEFECTDOJO_URL/API_KEY");
  }

  const productId = await dojo.ensureProduct(ctx.scope.name);
  const now = new Date();
  const engagementId = await dojo.createEngagement({
    productId,
    name: `Sentinel run ${ctx.runId}`,
    startDate: ymd(now),
    endDate: ymd(now),
    scopeRef: `${ctx.scope.authorization_ref} (by ${ctx.scope.authorized_by}, scopeHash ${ctx.scopeHash.slice(0, 12)})`,
  });

  let importedTests = 0;
  for (const artifact of scan.artifacts) {
    try {
      const test = await dojo.importScan({
        engagementId,
        scanType: artifact.dojoScanType,
        filePath: artifact.filePath,
      });
      importedTests++;
      await audit({
        runId: ctx.runId,
        actor: ctx.actor,
        action: "IMPORT",
        detail: { tool: artifact.tool, scanType: artifact.dojoScanType, testId: test.testId },
      });
    } catch (err) {
      ctx.log.error({ err, artifact: artifact.filePath }, "import: artifact failed");
    }
  }

  await prisma.run.update({
    where: { id: ctx.runId },
    data: { defectDojoProductId: productId, defectDojoEngagementId: engagementId },
  });

  ctx.log.info({ productId, engagementId, importedTests }, "import: complete");
  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "STAGE_COMPLETE",
    detail: { stage: "import", productId, engagementId, importedTests },
  });
  return { productId, engagementId, importedTests };
}
