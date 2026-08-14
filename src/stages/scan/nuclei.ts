import { writeFile } from "node:fs/promises";
import path from "node:path";
import { run, toolExists } from "../../lib/exec.js";
import { audit } from "../../lib/audit.js";
import { rawDir } from "../../lib/paths.js";
import type { RunContext } from "../../core/context.js";
import type { ScanArtifact } from "./artifacts.js";

/**
 * nuclei — templated web/cve/misconfig/exposure checks over alive in-scope URLs.
 *
 * Targets are fed via stdin (never a shell string). Auth headers are injected so
 * scanning goes past login. Rate limited per scope. Non-destructive template
 * tags only; nuclei's intrusive fuzzing is intentionally NOT enabled here even
 * under --allow-destructive (Phase 1 stays safe by default).
 */
export async function runNuclei(ctx: RunContext, urls: string[]): Promise<ScanArtifact | null> {
  if (urls.length === 0) return null;
  if (!(await toolExists("nuclei", ["-version"]))) {
    ctx.log.warn("scan: nuclei not installed — skipping");
    return null;
  }

  const outPath = path.join(rawDir(ctx.runId), "nuclei.jsonl");
  const args = [
    "-jsonl",
    "-silent",
    "-no-color",
    "-tags",
    "cve,misconfiguration,exposure,tech",
    "-rate-limit",
    String(ctx.scope.rate_limit_rps),
  ];
  for (const line of ctx.auth.headerLines) {
    args.push("-H", line);
  }
  if (!ctx.allowDestructive) {
    // Belt-and-suspenders: exclude template tags that can mutate state.
    args.push("-exclude-tags", "dos,fuzz,intrusive,sqli-blind");
  }

  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "TOOL_EXEC",
    scopeHash: ctx.scopeHash,
    detail: { tool: "nuclei", stage: "scan", targets: urls.length, allowDestructive: ctx.allowDestructive },
  });

  try {
    const { stdout } = await run("nuclei", args, {
      input: urls.join("\n") + "\n",
      allowNonZeroExit: true,
      timeoutMs: 30 * 60 * 1000,
    });
    await writeFile(outPath, stdout, "utf8");
    ctx.log.info({ outPath }, "scan: nuclei complete");
    return { tool: "nuclei", dojoScanType: "Nuclei Scan", filePath: outPath, format: "jsonl", target: "aggregate" };
  } catch (err) {
    ctx.log.error({ err }, "scan: nuclei failed");
    return null;
  }
}
