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
  const baseOutDir = path.join(rawDir(ctx.runId), "sqlmap");
  // Build ONE invocation per signature up front — each with its OWN output dir so
  // same-host targets never overwrite each other's target.txt / session.sqlite.
  const invocations = planSqlmapInvocations(tool.baseArgs, targets, cfg, baseOutDir, ctx.auth.headerLines);
  ctx.log.info(
    { targets: invocations.map((i) => i.url) },
    "scan: sqlmap invocations (one -u run per signature, isolated output dir)",
  );

  const findings: GenericFinding[] = [];
  const startedAt = Date.now();
  let done = 0;
  let budgetHit = false;
  const hb = startHeartbeat(ctx, "scan", "sqlmap", { total: invocations.length, getDone: () => done });
  try {
    for (const inv of invocations) {
      // Overall time budget: stop launching new targets once exceeded.
      if (Date.now() - startedAt >= cfg.budgetMs) {
        budgetHit = true;
        ctx.log.warn(
          { done, total: invocations.length, budgetMs: cfg.budgetMs },
          "scan: sqlmap overall budget reached — stopping (keeping findings so far)",
        );
        ctx.bus.stageProgress("scan", `sqlmap budget reached at ${done}/${invocations.length} — kept findings so far`, false);
        break;
      }

      // One visible line per target so all N runs are confirmable.
      ctx.bus.stageProgress("scan", `sqlmap testing ${inv.url}`, false);
      ctx.log.info({ url: inv.url, outDir: inv.outDir }, "scan: sqlmap testing target");
      try {
        const res = await run(tool.file, inv.args, {
          allowNonZeroExit: true,
          tolerateTimeout: true,
          timeoutMs: cfg.targetTimeoutMs,
        });
        findings.push(...parseSqlmapStdout(res.stdout, inv.url));
        if (res.timedOut) ctx.log.warn({ url: inv.url }, "scan: sqlmap PARTIAL (target timeout) — kept parsed injection points");
      } catch (err) {
        ctx.log.error({ err, url: inv.url }, "scan: sqlmap failed for url");
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

/** sqlmap speed/depth knobs used to build an invocation. */
export interface SqlmapCfg {
  level: number;
  risk: number;
  technique: string;
  threads: number;
  requestTimeoutSec: number;
  retries: number;
}

export interface SqlmapInvocation {
  url: string;
  outDir: string;
  args: string[];
}

/**
 * Per-target output dir. All signatures share one host (testasp.vulnweb.com), so
 * a single output dir would collide (sqlmap namespaces by host and overwrites
 * target.txt/session per host). A unique dir per target keeps every run isolated.
 */
export function sqlmapTargetOutDir(baseDir: string, url: string, index: number): string {
  const slug = createHash("sha1").update(url).digest("hex").slice(0, 12);
  return path.join(baseDir, `t${index}_${slug}`);
}

/** Build the full sqlmap argv for a SINGLE target URL. */
export function buildSqlmapArgs(
  baseArgs: string[],
  url: string,
  cfg: SqlmapCfg,
  outDir: string,
  headerLines: string[] = [],
): string[] {
  const args = [
    ...baseArgs,
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
  for (const line of headerLines) args.push("-H", line);
  return args;
}

/**
 * Plan ONE sqlmap invocation per signature — each with its own isolated output
 * dir. This is the seam that guarantees every deduped signature is tested (never
 * collapsed to one) and is unit-testable without executing sqlmap.
 */
export function planSqlmapInvocations(
  baseArgs: string[],
  targets: string[],
  cfg: SqlmapCfg,
  baseOutDir: string,
  headerLines: string[] = [],
): SqlmapInvocation[] {
  return targets.map((url, index) => {
    const outDir = sqlmapTargetOutDir(baseOutDir, url, index);
    return { url, outDir, args: buildSqlmapArgs(baseArgs, url, cfg, outDir, headerLines) };
  });
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
