import path from "node:path";
import { createHash } from "node:crypto";
import { run } from "../../lib/exec.js";
import { audit } from "../../lib/audit.js";
import { rawDir } from "../../lib/paths.js";
import { LIMITS } from "../../config/limits.js";
import { startHeartbeat } from "../../lib/progress.js";
import { gate, type RunContext } from "../../core/context.js";
import { resolveSqlmap } from "./resolve.js";
import { writeGenericFindingsFile, type GenericFinding } from "./generic.js";
import type { ScanArtifact } from "./artifacts.js";

/**
 * sqlmap — active SQL injection. DESTRUCTIVE: only invoked when the destructive
 * gate is open.
 *
 * Practical runtime:
 *   - targets are deduped by (path + param NAME) so ?id=1 / ?id=2 count once,
 *     then capped to LIMITS.maxInjectionTargets distinct signatures;
 *   - fast flags: low level/risk, fast techniques only (BEU), threads, batch;
 *   - a HARD per-target exec timeout (not 20 min each) plus an OVERALL wall-clock
 *     budget that stops starting new targets once exceeded;
 *   - partial capture: a killed target still contributes whatever injection
 *     points were confirmed in its stdout.
 */
/**
 * @param signatures ALREADY-deduped injection signatures — the SAME capped list
 *   dalfox receives (see scan/index.ts). Never the raw param URLs.
 */
export async function runSqlmap(ctx: RunContext, signatures: string[]): Promise<ScanArtifact | null> {
  if (signatures.length === 0) return null;
  const tool = await resolveSqlmap();
  if (!tool) {
    ctx.log.warn("scan: sqlmap not installed — skipping (install via scripts/setup.sh)");
    return null;
  }

  // Input is already deduped + capped upstream. Re-gate defensively.
  const targets: string[] = [];
  for (const u of signatures) {
    if ((await gate(ctx, u)).allowed) targets.push(u);
  }
  if (targets.length === 0) return null;
  ctx.log.info({ signatures: targets.length }, "scan: sqlmap running over deduped signatures");

  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "TOOL_EXEC",
    scopeHash: ctx.scopeHash,
    detail: { tool: "sqlmap", stage: "scan", targets: targets.length, allowDestructive: true },
  });

  const cfg = LIMITS.sqlmap;
  const outDir = path.join(rawDir(ctx.runId), "sqlmap");
  const findings: GenericFinding[] = [];
  const startedAt = Date.now();
  let done = 0;
  let budgetHit = false;
  const hb = startHeartbeat(ctx, "scan", "sqlmap", { total: targets.length, getDone: () => done });
  try {
    for (const url of targets) {
      // Overall time budget: stop launching new targets once exceeded.
      if (Date.now() - startedAt >= cfg.budgetMs) {
        budgetHit = true;
        ctx.log.warn(
          { done, total: targets.length, budgetMs: cfg.budgetMs },
          "scan: sqlmap overall budget reached — stopping (keeping findings so far)",
        );
        ctx.bus.stageProgress("scan", `sqlmap budget reached at ${done}/${targets.length} — kept findings so far`, false);
        break;
      }

      const args = [
        ...tool.baseArgs,
        "-u",
        url,
        "--batch",
        "--disable-coloring",
        `--level=${cfg.level}`,
        `--risk=${cfg.risk}`,
        `--technique=${cfg.technique}`,
        `--threads=${cfg.threads}`,
        `--timeout=${cfg.requestTimeoutSec}`,
        `--retries=${cfg.retries}`,
        "--smart",
        `--output-dir=${outDir}`,
      ];
      for (const line of ctx.auth.headerLines) {
        args.push("-H", line);
      }
      try {
        const res = await run(tool.file, args, {
          allowNonZeroExit: true,
          tolerateTimeout: true,
          timeoutMs: cfg.targetTimeoutMs,
        });
        findings.push(...parseSqlmapStdout(res.stdout, url));
        if (res.timedOut) ctx.log.warn({ url }, "scan: sqlmap PARTIAL (target timeout) — kept parsed injection points");
      } catch (err) {
        ctx.log.error({ err, url }, "scan: sqlmap failed for url");
      }
      done++;
    }
  } finally {
    hb.stop();
  }

  if (findings.length === 0) {
    ctx.log.info({ budgetHit }, "scan: sqlmap found no SQL injection");
    return null;
  }

  const outPath = path.join(rawDir(ctx.runId), "sqlmap.generic.json");
  await writeGenericFindingsFile(outPath, findings);
  ctx.log.info({ outPath, findings: findings.length, done, budgetHit }, "scan: sqlmap complete");
  return { tool: "sqlmap", dojoScanType: "Generic Findings Import", filePath: outPath, format: "json", target: "aggregate" };
}

/**
 * Parse sqlmap stdout for confirmed injection points. sqlmap prints blocks like:
 *   Parameter: id (GET)
 *       Type: boolean-based blind
 *       Title: AND boolean-based blind - WHERE or HAVING clause
 *       Payload: id=1 AND 1234=1234
 */
export function parseSqlmapStdout(stdout: string, url: string): GenericFinding[] {
  const lines = stdout.split(/\r?\n/);
  const findings: GenericFinding[] = [];
  let current: { param: string; method: string; types: string[]; titles: string[] } | null = null;

  const flush = (): void => {
    if (!current) return;
    const evidence = current.titles.length ? current.titles.join("; ") : current.types.join("; ");
    findings.push({
      sourceTool: "sqlmap",
      title: `SQL injection on parameter "${current.param}" (${current.method})`,
      description: `sqlmap confirmed SQL injection. Types: ${current.types.join(", ") || "unknown"}.`,
      severity: "HIGH",
      cwe: 89,
      endpoint: url,
      uniqueId: createHash("sha256").update(`sqlmap|${url}|${current.param}`).digest("hex").slice(0, 32),
      evidence: evidence || null,
    });
    current = null;
  };

  for (const raw of lines) {
    const line = raw.trim();
    const paramMatch = line.match(/^Parameter:\s*(.+?)\s*\((GET|POST|COOKIE|HEADER|URI)\)/i);
    if (paramMatch) {
      flush();
      current = { param: paramMatch[1]!, method: paramMatch[2]!.toUpperCase(), types: [], titles: [] };
      continue;
    }
    if (current) {
      const typeMatch = line.match(/^Type:\s*(.+)$/i);
      if (typeMatch) current.types.push(typeMatch[1]!);
      const titleMatch = line.match(/^Title:\s*(.+)$/i);
      if (titleMatch) current.titles.push(titleMatch[1]!);
      // A separator or blank line after a block ends the current parameter.
      if (line === "---" || line === "") {
        // keep accumulating across blank lines within a block; "---" ends it.
        if (line === "---") flush();
      }
    }
  }
  flush();
  return findings;
}
