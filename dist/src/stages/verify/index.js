import { prisma } from "../../db/client.js";
import { audit } from "../../lib/audit.js";
import { gate } from "../../core/context.js";
import { classify } from "./classify.js";
import { VERIFIERS } from "./verifiers.js";
function toUnified(row) {
    return {
        sourceTool: row.sourceTool,
        templateId: row.templateId,
        name: row.name,
        target: row.target,
        matchedLocation: row.matchedLocation,
        severity: row.severity,
        cvss: row.cvss,
        epss: row.epss,
        evidence: row.evidence,
        raw: row.raw,
    };
}
export async function runVerify(ctx) {
    ctx.log.info("verify: starting (Phase 2 scaffold)");
    await audit({ runId: ctx.runId, actor: ctx.actor, action: "STAGE_START", detail: { stage: "verify" } });
    const rows = await prisma.finding.findMany({ where: { runId: ctx.runId } });
    const result = { verified: 0, lowConfidence: 0, manual: 0, neverAuto: 0 };
    for (const row of rows) {
        const finding = toUnified(row);
        const cls = classify(finding);
        if (cls === "NEVER_AUTO") {
            await setStatus(row.id, "NEVER_AUTO");
            result.neverAuto++;
            continue;
        }
        if (cls === "MANUAL") {
            await setStatus(row.id, "MANUAL_REVIEW");
            result.manual++;
            continue;
        }
        // AUTO: re-gate the replay target, then run a matching verifier.
        const replayTarget = finding.matchedLocation ?? finding.target;
        const decision = await gate(ctx, replayTarget);
        if (!decision.allowed) {
            await setStatus(row.id, "MANUAL_REVIEW");
            result.manual++;
            continue;
        }
        const verifier = VERIFIERS.find((v) => v.applies(finding));
        if (!verifier) {
            await setStatus(row.id, "MANUAL_REVIEW");
            result.manual++;
            continue;
        }
        try {
            const outcome = await verifier.verify(finding, ctx.auth.headerMap);
            await setStatus(row.id, outcome.outcome === "VERIFIED" ? "VERIFIED" : "LOW_CONFIDENCE");
            if (outcome.outcome === "VERIFIED")
                result.verified++;
            else
                result.lowConfidence++;
            // TODO(Phase 2): attach outcome.evidence to the DefectDojo finding as a note.
        }
        catch (err) {
            ctx.log.warn({ err, finding: finding.name }, "verify: replay failed");
            await setStatus(row.id, "LOW_CONFIDENCE");
            result.lowConfidence++;
        }
    }
    ctx.log.info(result, "verify: complete");
    await audit({ runId: ctx.runId, actor: ctx.actor, action: "STAGE_COMPLETE", detail: { stage: "verify", ...result } });
    return result;
}
async function setStatus(findingId, status) {
    await prisma.finding.update({ where: { id: findingId }, data: { verificationStatus: status } });
}
//# sourceMappingURL=index.js.map