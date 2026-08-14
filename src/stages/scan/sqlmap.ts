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
 * gate is open. Runs per in-scope param URL with --batch (non-interactive), at
 * low level/risk. Injection points are parsed from sqlmap's stdout.
 *
 * Partial capture: a kill still yields whatever stdout was captured.
 */
export async function runSqlmap(ctx: RunContext, paramUrls: string[]): Promise<ScanArtifact | null> {
  if (paramUrls.length === 0) return null;
  const tool = await resolveSqlmap();
  if (!tool) {
    ctx.log.warn("scan: sqlmap not installed — skipping (install via scripts/setup.sh)");
    return null;
  }

  // Defensive re-gate; cap targets.
  const targets: string[] = [];
  for (const u of paramUrls) {
    if ((await gate(ctx, u)).allowed) targets.push(u);
    if (targets.length >= LIMITS.maxInjectionTargets) break;
  }
  if (targets.length === 0) return null;

  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "TOOL_EXEC",
    scopeHash: ctx.scopeHash,
    detail: { tool: "sqlmap", stage: "scan", targets: targets.length, allowDestructive: true },
  });

  const outDir = path.join(rawDir(ctx.runId), "sqlmap");
  const findings: GenericFinding[] = [];
  let done = 0;
  const hb = startHeartbeat(ctx, "scan", "sqlmap", { total: targets.length, getDone: () => done });
  try {
    for (const url of targets) {
      const args = [
        ...tool.baseArgs,
        "-u",
        url,
        "--batch",
        "--disable-coloring",
        "--level=1",
        "--risk=1",
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
          timeoutMs: LIMITS.toolTimeoutMs.sqlmap,
        });
        findings.push(...parseSqlmapStdout(res.stdout, url));
        if (res.timedOut) ctx.log.warn({ url }, "scan: sqlmap PARTIAL (timed out) — kept parsed injection points");
      } catch (err) {
        ctx.log.error({ err, url }, "scan: sqlmap failed for url");
      }
      done++;
    }
  } finally {
    hb.stop();
  }

  if (findings.length === 0) {
    ctx.log.info("scan: sqlmap found no SQL injection");
    return null;
  }

  const outPath = path.join(rawDir(ctx.runId), "sqlmap.generic.json");
  await writeGenericFindingsFile(outPath, findings);
  ctx.log.info({ outPath, findings: findings.length }, "scan: sqlmap complete");
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
