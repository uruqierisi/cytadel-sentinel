import path from "node:path";
import { run } from "../../lib/exec.js";
import { audit } from "../../lib/audit.js";
import { rawDir } from "../../lib/paths.js";
import { resolveTestssl } from "./resolve.js";
import type { RunContext } from "../../core/context.js";
import type { ScanArtifact } from "./artifacts.js";

/**
 * testssl.sh — TLS/SSL configuration issues, one CSV per host. DefectDojo's
 * "Testssl Scan" parser consumes the CSV (--csvfile) output.
 *
 * Non-destructive (read-only TLS negotiation). host:port passed as argv only.
 */
export async function runTestssl(ctx: RunContext, hostports: string[]): Promise<ScanArtifact[]> {
  if (hostports.length === 0) return [];
  const tool = await resolveTestssl();
  if (!tool) {
    ctx.log.warn("scan: testssl.sh not installed — skipping");
    return [];
  }

  const artifacts: ScanArtifact[] = [];
  for (const hp of hostports) {
    const safeName = hp.replace(/[^a-z0-9.-]+/gi, "_");
    const outPath = path.join(rawDir(ctx.runId), `testssl-${safeName}.csv`);
    await audit({
      runId: ctx.runId,
      actor: ctx.actor,
      action: "TOOL_EXEC",
      scopeHash: ctx.scopeHash,
      target: hp,
      detail: { tool: "testssl", stage: "scan" },
    });
    try {
      await run(
        tool.file,
        [...tool.baseArgs, "--csvfile", outPath, "--quiet", "--color", "0", "--warnings", "off", hp],
        { allowNonZeroExit: true, timeoutMs: 10 * 60 * 1000 },
      );
      artifacts.push({ tool: "testssl", dojoScanType: "Testssl Scan", filePath: outPath, format: "csv", target: hp });
    } catch (err) {
      ctx.log.error({ err, hp }, "scan: testssl failed for host");
    }
  }
  ctx.log.info({ hosts: hostports.length, artifacts: artifacts.length }, "scan: testssl complete");
  return artifacts;
}
