import path from "node:path";
import { createHash } from "node:crypto";
import { run } from "../../lib/exec.js";
import { audit } from "../../lib/audit.js";
import { rawDir } from "../../lib/paths.js";
import { LIMITS } from "../../config/limits.js";
import { startHeartbeat } from "../../lib/progress.js";
import { parseJsonArrayLoose } from "../../lib/parse.js";
import { normalizeSeverity } from "../normalize/types.js";
import { gate, type RunContext } from "../../core/context.js";
import { resolveDalfox } from "./resolve.js";
import { writeGenericFindingsFile, type GenericFinding } from "./generic.js";
import type { ScanArtifact } from "./artifacts.js";

/**
 * dalfox — active XSS injection. DESTRUCTIVE: only invoked when the destructive
 * gate is open (scope allow_destructive AND CLI --allow-destructive). The caller
 * (scan orchestrator) enforces that; this wrapper assumes it may inject.
 *
 * Targets are in-scope param URLs, fed via stdin (dalfox `pipe`), split into
 * batches under an overall wall-clock budget so dalfox FINISHES each batch and
 * emits a COMPLETE JSON array instead of being SIGTERM-killed mid-write. If a
 * batch is still killed, its truncated array is parsed leniently
 * (parseJsonArrayLoose) so every PoC emitted before the cut becomes a finding.
 */

/**
 * Map one dalfox PoC object (`--format json`) into a unified GenericFinding.
 *
 * The fields ARE present in dalfox's raw JSON — param, data (the injected URL),
 * payload, evidence, cwe, severity — they were previously dropped because the
 * truncated array failed to parse at all. Wire them all through so the report
 * carries the parameter, URL, payload and evidence.
 */
export function dalfoxPocToFinding(p: Record<string, unknown>): GenericFinding {
  const url = String(p["data"] ?? p["url"] ?? "");
  const param = String(p["param"] ?? "");
  const payload = String(p["payload"] ?? "");
  const injectType = String(p["inject_type"] ?? p["type"] ?? "reflected");
  const rawEvidence = String(p["evidence"] ?? p["message_str"] ?? "");
  const cwe = Number(String(p["cwe"] ?? "").replace(/\D+/g, "")) || 79;
  const severity = normalizeSeverity(String(p["severity"] ?? "high"));

  // Evidence carries BOTH the payload and dalfox's reflection snippet so the
  // finding is actionable on its own.
  const evidenceParts: string[] = [];
  if (payload) evidenceParts.push(`payload: ${payload}`);
  if (rawEvidence) evidenceParts.push(`evidence: ${rawEvidence}`);
  const evidence = evidenceParts.join(" | ") || null;

  const description =
    `dalfox confirmed a cross-site scripting vector on parameter "${param}"` +
    (payload ? ` using payload: ${payload}.` : ".");

  return {
    sourceTool: "dalfox",
    title: `XSS (${injectType}) on parameter "${param}"`,
    description,
    severity,
    cwe,
    endpoint: url,
    // Include inject type + payload so two distinct PoCs on the SAME param/URL
    // stay distinct through dedupe instead of collapsing to one.
    uniqueId: createHash("sha256")
      .update(`dalfox|${url}|${param}|${injectType}|${payload}`)
      .digest("hex")
      .slice(0, 32),
    evidence,
  };
}

/** Split an array into fixed-size chunks. */
function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/**
 * @param signatures ALREADY-deduped injection signatures (path + param NAME),
 *   the SAME capped list sqlmap receives — see scan/index.ts. dalfox must never
 *   be handed the raw param URLs, or it burns its budget on duplicate params.
 */
export async function runDalfox(ctx: RunContext, signatures: string[]): Promise<ScanArtifact | null> {
  if (signatures.length === 0) return null;
  const tool = await resolveDalfox();
  if (!tool) {
    ctx.log.warn("scan: dalfox not installed — skipping (install via scripts/setup.sh)");
    return null;
  }

  // Input is already deduped + capped upstream. Re-gate defensively; never
  // re-expand it.
  const targets: string[] = [];
  for (const u of signatures) {
    if ((await gate(ctx, u)).allowed) targets.push(u);
  }
  if (targets.length === 0) return null;
  ctx.log.info({ signatures: targets.length }, "scan: dalfox running over deduped signatures");
  ctx.bus.stageProgress("scan", `dalfox: ${targets.length} deduped signature(s)`, false);

  const cfg = LIMITS.dalfox;
  const args = [
    ...tool.baseArgs,
    "pipe",
    "--format",
    "json",
    "--silence",
    "--no-color",
    "--no-spinner",
    // Speed flags so dalfox finishes and emits a complete JSON array.
    "--worker",
    String(cfg.worker),
    "--timeout",
    String(cfg.requestTimeoutSec),
  ];
  if (cfg.skipBav) args.push("--skip-bav");
  if (cfg.blindCallback) args.push("--blind", cfg.blindCallback);
  for (const line of ctx.auth.headerLines) {
    args.push("-H", line);
  }

  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "TOOL_EXEC",
    scopeHash: ctx.scopeHash,
    detail: { tool: "dalfox", stage: "scan", targets: targets.length, allowDestructive: true },
  });

  const batches = chunk(targets, cfg.batchSize);
  const startedAt = Date.now();
  const byId = new Map<string, GenericFinding>();
  let done = 0;
  let budgetHit = false;
  let anyTimeout = false;
  const hb = startHeartbeat(ctx, "scan", "dalfox", { total: targets.length, getDone: () => done });
  try {
    for (const batch of batches) {
      // Overall time budget: stop launching new batches once exceeded.
      if (Date.now() - startedAt >= cfg.budgetMs) {
        budgetHit = true;
        ctx.log.warn(
          { done, total: targets.length, budgetMs: cfg.budgetMs },
          "scan: dalfox overall budget reached — stopping (keeping findings so far)",
        );
        ctx.bus.stageProgress("scan", `dalfox budget reached at ${done}/${targets.length} — kept findings so far`, false);
        break;
      }
      try {
        const res = await run(tool.file, args, {
          input: batch.join("\n") + "\n",
          allowNonZeroExit: true,
          tolerateTimeout: true,
          timeoutMs: cfg.batchTimeoutMs,
        });
        // Lenient array parse: a killed batch leaves an unterminated array, but
        // every complete PoC before the cut is still recovered.
        for (const poc of parseJsonArrayLoose<Record<string, unknown>>(res.stdout)) {
          const finding = dalfoxPocToFinding(poc);
          if (!byId.has(finding.uniqueId)) byId.set(finding.uniqueId, finding);
        }
        if (res.timedOut) {
          anyTimeout = true;
          ctx.log.warn({ batch: batch.length }, "scan: dalfox PARTIAL (batch timeout) — kept parsed PoCs");
        }
      } catch (err) {
        ctx.log.error({ err }, "scan: dalfox batch errored — attempting partial capture");
      }
      done += batch.length;
    }
  } finally {
    hb.stop();
  }

  const findings = [...byId.values()];
  if (findings.length === 0) {
    ctx.log.info({ budgetHit, anyTimeout }, "scan: dalfox found no XSS");
    return null;
  }

  const outPath = path.join(rawDir(ctx.runId), "dalfox.generic.json");
  await writeGenericFindingsFile(outPath, findings);
  ctx.log.info({ outPath, findings: findings.length, done, budgetHit, anyTimeout }, "scan: dalfox complete");
  if (anyTimeout || budgetHit) {
    ctx.bus.stageProgress("scan", `dalfox kept ${findings.length} XSS PoC(s) (partial/budget)`, false);
  }
  return { tool: "dalfox", dojoScanType: "Generic Findings Import", filePath: outPath, format: "json", target: "aggregate" };
}
