import path from "node:path";
import { createHash } from "node:crypto";
import { run } from "../../lib/exec.js";
import { audit } from "../../lib/audit.js";
import { rawDir } from "../../lib/paths.js";
import { LIMITS } from "../../config/limits.js";
import { startHeartbeat } from "../../lib/progress.js";
import { parseJsonLoose } from "../../lib/parse.js";
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
 * Targets are in-scope param URLs, fed via stdin (dalfox `pipe`). Auth headers
 * injected. Partial capture: a kill still yields whatever PoCs were emitted.
 */
export async function runDalfox(ctx: RunContext, paramUrls: string[]): Promise<ScanArtifact | null> {
  if (paramUrls.length === 0) return null;
  const tool = await resolveDalfox();
  if (!tool) {
    ctx.log.warn("scan: dalfox not installed — skipping (install via scripts/setup.sh)");
    return null;
  }

  // Defensive re-gate; cap the number of injection targets.
  const targets: string[] = [];
  for (const u of paramUrls) {
    if ((await gate(ctx, u)).allowed) targets.push(u);
    if (targets.length >= LIMITS.maxInjectionTargets) break;
  }
  if (targets.length === 0) return null;

  const args = [...tool.baseArgs, "pipe", "--format", "json", "--silence", "--no-color", "--no-spinner"];
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

  const hb = startHeartbeat(ctx, "scan", "dalfox", { total: targets.length });
  let stdout = "";
  let timedOut = false;
  try {
    const res = await run(tool.file, args, {
      input: targets.join("\n") + "\n",
      allowNonZeroExit: true,
      tolerateTimeout: true,
      timeoutMs: LIMITS.toolTimeoutMs.dalfox,
    });
    stdout = res.stdout;
    timedOut = res.timedOut;
  } catch (err) {
    ctx.log.error({ err }, "scan: dalfox errored — attempting partial capture");
  } finally {
    hb.stop();
  }

  const pocs = parseJsonLoose<Record<string, unknown>>(stdout);
  const findings: GenericFinding[] = pocs.map((p) => {
    const url = String(p["data"] ?? p["url"] ?? "");
    const param = String(p["param"] ?? "");
    const cweRaw = String(p["cwe"] ?? "");
    const cwe = Number(cweRaw.replace(/\D+/g, "")) || 79;
    const evidence = String(p["evidence"] ?? p["message_str"] ?? p["payload"] ?? "");
    return {
      sourceTool: "dalfox",
      title: `XSS (${String(p["type"] ?? "reflected")}) on parameter "${param}"`,
      description: `dalfox confirmed a cross-site scripting vector. ${evidence}`.trim(),
      severity: normalizeSeverity(String(p["severity"] ?? "high")),
      cwe,
      endpoint: url,
      uniqueId: createHash("sha256").update(`dalfox|${url}|${param}`).digest("hex").slice(0, 32),
      evidence: evidence || null,
    };
  });

  if (findings.length === 0 && !timedOut) {
    ctx.log.info("scan: dalfox found no XSS");
    return null;
  }

  const outPath = path.join(rawDir(ctx.runId), "dalfox.generic.json");
  await writeGenericFindingsFile(outPath, findings);
  ctx.log.info({ outPath, findings: findings.length, timedOut }, "scan: dalfox complete");
  if (timedOut) ctx.bus.stageProgress("scan", `dalfox timed out — kept ${findings.length} PoC(s)`, false);
  return { tool: "dalfox", dojoScanType: "Generic Findings Import", filePath: outPath, format: "json", target: "aggregate" };
}
