import { prisma } from "../../db/client.js";
import { audit } from "../../lib/audit.js";
import { gate, type RunContext } from "../../core/context.js";
import type { UnifiedFinding } from "../normalize/types.js";
import { classify } from "./classify.js";
import { VERIFIERS } from "./verifiers.js";
import type { VerificationResult } from "./types.js";

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

function toUnified(row: {
  sourceTool: string;
  templateId: string | null;
  name: string;
  target: string;
  matchedLocation: string | null;
  severity: string;
  cvss: number | null;
  epss: number | null;
  evidence: string | null;
  raw: unknown;
}): UnifiedFinding {
  return {
    sourceTool: row.sourceTool,
    templateId: row.templateId,
    name: row.name,
    target: row.target,
    matchedLocation: row.matchedLocation,
    severity: row.severity as UnifiedFinding["severity"],
    cvss: row.cvss,
    epss: row.epss,
    evidence: row.evidence,
    raw: row.raw,
  };
}

export async function runVerify(ctx: RunContext): Promise<VerifyResult> {
  ctx.log.info("verify: starting (Phase 2 scaffold)");
  await audit({ runId: ctx.runId, actor: ctx.actor, action: "STAGE_START", detail: { stage: "verify" } });

  const rows = await prisma.finding.findMany({ where: { runId: ctx.runId } });
  const result: VerifyResult = { verified: 0, lowConfidence: 0, manual: 0, neverAuto: 0 };

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
      const outcome: VerificationResult = await verifier.verify(finding, ctx.auth.headerMap);
      await setStatus(row.id, outcome.outcome === "VERIFIED" ? "VERIFIED" : "LOW_CONFIDENCE");
      if (outcome.outcome === "VERIFIED") result.verified++;
      else result.lowConfidence++;
      // TODO(Phase 2): attach outcome.evidence to the DefectDojo finding as a note.
    } catch (err) {
      ctx.log.warn({ err, finding: finding.name }, "verify: replay failed");
      await setStatus(row.id, "LOW_CONFIDENCE");
      result.lowConfidence++;
    }
  }

  ctx.log.info(result, "verify: complete");
  await audit({ runId: ctx.runId, actor: ctx.actor, action: "STAGE_COMPLETE", detail: { stage: "verify", ...result } });
  return result;
}

async function setStatus(
  findingId: string,
  status: "VERIFIED" | "LOW_CONFIDENCE" | "MANUAL_REVIEW" | "NEVER_AUTO",
): Promise<void> {
  await prisma.finding.update({ where: { id: findingId }, data: { verificationStatus: status } });
}
