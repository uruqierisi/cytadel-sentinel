import { writeFile } from "node:fs/promises";
import path from "node:path";
import { prisma } from "../../db/client.js";
import { audit } from "../../lib/audit.js";
import { runDir, ensureRunDirs } from "../../lib/paths.js";
import { authSecretValues, scrubString } from "../../lib/scrub.js";
import { coverageLimitations } from "../../core/coverage.js";
import { renderHtml } from "./template.js";
const EMPTY_COUNTS = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
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
    // Source of truth = the local normalized findings persisted this run. This is
    // exactly what the CLI counts and what was imported to DefectDojo, so all three
    // agree. The DefectDojo engagement is still linked (below) for triage.
    const findings = await collectFromLocal(ctx.runId);
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
        coverage: {
            hosts: ctx.coverage.hosts,
            endpoints: ctx.coverage.endpoints,
            params: ctx.coverage.params,
            authState: ctx.coverage.auth.state,
            authMode: ctx.coverage.auth.mode,
            candidatesBySource: ctx.coverage.candidatesBySource,
            injection: { get: ctx.coverage.injection.get, post: ctx.coverage.injection.post, ran: ctx.coverage.injection.ran },
            tools: ctx.coverage.tools,
            limitations: coverageLimitations(ctx.coverage),
        },
    };
    const dir = runDir(ctx.runId);
    const htmlPath = path.join(dir, "report.html");
    const jsonPath = path.join(dir, "report.json");
    // Defense-in-depth: the report is built from local findings (which shouldn't
    // contain auth material), but scrub the rendered output anyway so a session
    // token can never reach the client-facing report.
    const secrets = authSecretValues(ctx.auth);
    await writeFile(htmlPath, scrubString(renderHtml(data), secrets), "utf8");
    await writeFile(jsonPath, scrubString(JSON.stringify(data, null, 2), secrets), "utf8");
    await prisma.run.update({ where: { id: ctx.runId }, data: { reportPath: htmlPath } });
    ctx.log.info({ htmlPath, jsonPath, findings: findings.length }, "report: complete");
    await audit({
        runId: ctx.runId,
        actor: ctx.actor,
        action: "REPORT",
        detail: { htmlPath, jsonPath, findings: findings.length },
    });
    return { htmlPath, jsonPath, severityCounts, findingCount: findings.length };
}
//# sourceMappingURL=index.js.map