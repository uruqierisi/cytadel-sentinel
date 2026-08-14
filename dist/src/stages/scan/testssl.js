import path from "node:path";
import { run } from "../../lib/exec.js";
import { audit } from "../../lib/audit.js";
import { rawDir } from "../../lib/paths.js";
import { fileHasContent } from "../../lib/files.js";
import { LIMITS } from "../../config/limits.js";
import { startHeartbeat } from "../../lib/progress.js";
import { resolveTestssl } from "./resolve.js";
/**
 * testssl.sh — TLS/SSL configuration issues, one CSV per host. DefectDojo's
 * "Testssl Scan" parser consumes the CSV (--csvfile) output.
 *
 * Non-destructive (read-only TLS negotiation). host:port passed as argv only.
 */
export async function runTestssl(ctx, hostports) {
    if (hostports.length === 0)
        return [];
    const tool = await resolveTestssl();
    if (!tool) {
        ctx.log.warn("scan: testssl.sh not installed — skipping");
        return [];
    }
    const artifacts = [];
    let done = 0;
    const hb = startHeartbeat(ctx, "scan", "testssl", { total: hostports.length, getDone: () => done });
    try {
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
                const res = await run(tool.file, [...tool.baseArgs, "--csvfile", outPath, "--quiet", "--color", "0", "--warnings", "off", hp], { allowNonZeroExit: true, tolerateTimeout: true, timeoutMs: LIMITS.toolTimeoutMs.testssl });
                if (await fileHasContent(outPath)) {
                    artifacts.push({ tool: "testssl", dojoScanType: "Testssl Scan", filePath: outPath, format: "csv", target: hp });
                    if (res.timedOut)
                        ctx.log.warn({ hp, outPath }, "scan: testssl PARTIAL (timed out) — keeping CSV");
                }
                else if (res.timedOut) {
                    ctx.log.warn({ hp }, "scan: testssl timed out with no CSV — skipping host");
                }
            }
            catch (err) {
                ctx.log.error({ err, hp }, "scan: testssl failed for host");
            }
            done++;
        }
    }
    finally {
        hb.stop();
    }
    ctx.log.info({ hosts: hostports.length, artifacts: artifacts.length }, "scan: testssl complete");
    return artifacts;
}
//# sourceMappingURL=testssl.js.map