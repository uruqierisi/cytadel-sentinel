import { writeFile } from "node:fs/promises";
import path from "node:path";
import { prisma } from "../../db/client.js";
import { audit } from "../../lib/audit.js";
import { runDir, ensureRunDirs } from "../../lib/paths.js";
import { normalizeSeverity } from "../normalize/types.js";
import { DefectDojoClient } from "../../integrations/defectdojo/client.js";
import { renderHtml } from "./template.js";
const EMPTY_COUNTS = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
async function collectFromDefectDojo(engagementId) {
    try {
        const dojo = DefectDojoClient.fromEnv();
        const findings = await dojo.listFindings(engagementId);
        return findings
            .filter((f) => !f.false_p && !f.duplicate)
            .map((f) => ({
            title: f.title,
            severity: normalizeSeverity(f.severity),
            target: f.component_name ?? f.file_path ?? "(see DefectDojo)",
            sourceTool: "defectdojo",
            cve: f.cve ?? null,
            cvss: f.cvssv3_score ?? null,
            description: f.description ?? null,
            evidence: f.mitigation ?? null,
            verified: Boolean(f.verified),
            active: f.active ?? true,
        }));
    }
    catch {
        return null;
    }
}
async function collectFromLocal(runId) {
    const rows = await prisma.finding.findMany({ where: { runId }, orderBy: { severity: "desc" } });
    return rows.map((r) => ({
        title: r.name,
        severity: r.severity,
        target: r.target,
        sourceTool: r.sourceTool,
        cve: null,
        cvss: r.cvss ?? null,
        description: null,
        evidence: r.evidence ?? null,
        verified: r.verificationStatus === "VERIFIED",
        active: true,
    }));
}
export async function runReport(ctx, engagementId) {
    ctx.log.info({ engagementId }, "report: starting");
    await audit({ runId: ctx.runId, actor: ctx.actor, action: "STAGE_START", detail: { stage: "report" } });
    await ensureRunDirs(ctx.runId);
    const run = await prisma.run.findUniqueOrThrow({ where: { id: ctx.runId } });
    const assetCount = await prisma.asset.count({ where: { runId: ctx.runId } });
    let findings = engagementId ? await collectFromDefectDojo(engagementId) : null;
    if (!findings) {
        ctx.log.warn("report: falling back to local finding table (DefectDojo unavailable)");
        findings = await collectFromLocal(ctx.runId);
    }
    // Sort CRITICAL -> INFO and tally.
    const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    findings.sort((a, b) => rank[a.severity] - rank[b.severity]);
    const severityCounts = { ...EMPTY_COUNTS };
    for (const f of findings)
        severityCounts[f.severity]++;
    const data = {
        runId: ctx.runId,
        generatedAt: new Date().toISOString(),
        scope: {
            name: ctx.scope.name,
            authorizedBy: ctx.scope.authorized_by,
            authorizationRef: ctx.scope.authorization_ref,
            scopeHash: ctx.scopeHash,
            allowDestructive: ctx.allowDestructive,
        },
        actor: ctx.actor,
        startedAt: run.startedAt.toISOString(),
        finishedAt: (run.finishedAt ?? new Date()).toISOString(),
        assetCount,
        activeInjection: ctx.allowDestructive,
        engagementId,
        defectDojoUrl: process.env.DEFECTDOJO_URL?.replace(/\/+$/, "") ?? null,
        severityCounts,
        findings,
    };
    const dir = runDir(ctx.runId);
    const htmlPath = path.join(dir, "report.html");
    const jsonPath = path.join(dir, "report.json");
    await writeFile(htmlPath, renderHtml(data), "utf8");
    await writeFile(jsonPath, JSON.stringify(data, null, 2), "utf8");
    await prisma.run.update({ where: { id: ctx.runId }, data: { reportPath: htmlPath } });
    ctx.log.info({ htmlPath, jsonPath, findings: findings.length }, "report: complete");
    await audit({
        runId: ctx.runId,
        actor: ctx.actor,
        action: "REPORT",
        detail: { htmlPath, jsonPath, findings: findings.length },
    });
    return { htmlPath, jsonPath };
}
//# sourceMappingURL=index.js.map