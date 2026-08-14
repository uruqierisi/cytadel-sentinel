import path from "node:path";
import { run } from "../../lib/exec.js";
import { audit } from "../../lib/audit.js";
import { rawDir } from "../../lib/paths.js";
import { fileHasContent } from "../../lib/files.js";
import { LIMITS } from "../../config/limits.js";
import { startHeartbeat } from "../../lib/progress.js";
import { resolveNikto } from "./resolve.js";
/**
 * nikto — server-level web checks, one XML per target. DefectDojo's "Nikto Scan"
 * parser consumes the XML output. Auth cookie/header injected via -id/-H is not
 * uniform across nikto builds, so we pass the cookie via the -H style header
 * where supported and otherwise scan unauthenticated (logged).
 *
 * URL passed as argv only. Non-destructive by default (nikto is read-oriented).
 */
export async function runNikto(ctx, urls) {
    if (urls.length === 0)
        return [];
    const tool = await resolveNikto();
    if (!tool) {
        ctx.log.warn("scan: nikto not installed — skipping");
        return [];
    }
    const artifacts = [];
    let done = 0;
    const hb = startHeartbeat(ctx, "scan", "nikto", { total: urls.length, getDone: () => done });
    try {
        for (const url of urls) {
            const safeName = url.replace(/[^a-z0-9.-]+/gi, "_").slice(0, 80);
            const outPath = path.join(rawDir(ctx.runId), `nikto-${safeName}.xml`);
            const args = [...tool.baseArgs, "-h", url, "-Format", "xml", "-output", outPath, "-nointeractive", "-ask", "no"];
            // Inject session cookie where nikto supports it (-id user:pass is unrelated;
            // custom headers via -H). Cookie header is the common authenticated case.
            const cookie = ctx.auth.headerMap["Cookie"];
            if (cookie) {
                args.push("-H", `Cookie: ${cookie}`);
            }
            await audit({
                runId: ctx.runId,
                actor: ctx.actor,
                action: "TOOL_EXEC",
                scopeHash: ctx.scopeHash,
                target: url,
                detail: { tool: "nikto", stage: "scan", authenticated: Boolean(cookie) },
            });
            try {
                const res = await run(tool.file, args, {
                    allowNonZeroExit: true,
                    tolerateTimeout: true,
                    timeoutMs: LIMITS.toolTimeoutMs.nikto,
                });
                // Partial capture: only keep the artifact if nikto actually wrote XML. On a
                // kill the file is often 0 bytes — skip it rather than crash the pipeline.
                if (await fileHasContent(outPath)) {
                    artifacts.push({ tool: "nikto", dojoScanType: "Nikto Scan", filePath: outPath, format: "xml", target: url });
                    if (res.timedOut)
                        ctx.log.warn({ url, outPath }, "scan: nikto PARTIAL (timed out) — keeping XML");
                }
                else if (res.timedOut) {
                    ctx.log.warn({ url }, "scan: nikto timed out with no XML written — skipping host");
                }
            }
            catch (err) {
                ctx.log.error({ err, url }, "scan: nikto failed for url");
            }
            done++;
        }
    }
    finally {
        hb.stop();
    }
    ctx.log.info({ urls: urls.length, artifacts: artifacts.length }, "scan: nikto complete");
    return artifacts;
}
//# sourceMappingURL=nikto.js.map