import { readFile } from "node:fs/promises";
import { prisma } from "../../db/client.js";
import { audit } from "../../lib/audit.js";
import type { RunContext } from "../../core/context.js";
import type { ScanResult } from "../scan/index.js";
import type { ScanArtifact } from "../scan/artifacts.js";
import { dedupeKey, type UnifiedFinding } from "./types.js";
import { parseNuclei, parseNikto, parseTestssl, parseRetire } from "./parsers.js";

/**
 * Normalize stage: read each native scan artifact, map to UnifiedFinding, dedupe
 * within the run (key = tool + templateId + host + matchedLocation), and persist
 * Finding rows. Destructive-class findings are marked NEVER_AUTO for the
 * verification layer.
 */

export interface NormalizeResult {
  findings: UnifiedFinding[];
  persisted: number;
}

const DESTRUCTIVE_HINT = /(sqli|sql-injection|rce|command-injection|deserialization)/i;

async function parseArtifact(artifact: ScanArtifact): Promise<UnifiedFinding[]> {
  let content: string;
  try {
    content = await readFile(artifact.filePath, "utf8");
  } catch {
    return [];
  }
  switch (artifact.tool) {
    case "nuclei":
      return parseNuclei(content);
    case "testssl":
      return parseTestssl(content);
    case "nikto":
      return parseNikto(content);
    case "retirejs":
      return parseRetire(content);
    default:
      return [];
  }
}

export async function runNormalize(ctx: RunContext, scan: ScanResult): Promise<NormalizeResult> {
  ctx.log.info({ artifacts: scan.artifacts.length }, "normalize: starting");
  await audit({ runId: ctx.runId, actor: ctx.actor, action: "STAGE_START", detail: { stage: "normalize" } });

  // Collect + dedupe.
  const byKey = new Map<string, UnifiedFinding>();
  for (const artifact of scan.artifacts) {
    for (const finding of await parseArtifact(artifact)) {
      const key = dedupeKey(finding);
      if (!byKey.has(key)) byKey.set(key, finding);
    }
  }

  // Persist.
  let persisted = 0;
  for (const [key, f] of byKey) {
    const verificationStatus = DESTRUCTIVE_HINT.test(`${f.templateId ?? ""} ${f.name}`)
      ? "NEVER_AUTO"
      : "UNVERIFIED";
    await prisma.finding.upsert({
      where: { runId_dedupeKey: { runId: ctx.runId, dedupeKey: key } },
      create: {
        runId: ctx.runId,
        sourceTool: f.sourceTool,
        templateId: f.templateId ?? undefined,
        name: f.name,
        target: f.target,
        matchedLocation: f.matchedLocation ?? undefined,
        severity: f.severity,
        cvss: f.cvss ?? undefined,
        epss: f.epss ?? undefined,
        evidence: f.evidence ?? undefined,
        raw: f.raw as object,
        dedupeKey: key,
        verificationStatus,
      },
      update: {},
    });
    persisted++;
  }

  const findings = [...byKey.values()];
  ctx.log.info({ unique: findings.length, persisted }, "normalize: complete");
  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "STAGE_COMPLETE",
    detail: { stage: "normalize", unique: findings.length },
  });
  return { findings, persisted };
}
