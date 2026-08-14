import path from "node:path";
import { run } from "../../lib/exec.js";
import { audit } from "../../lib/audit.js";
import { rawDir } from "../../lib/paths.js";
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
            await run(tool.file, args, { allowNonZeroExit: true, timeoutMs: 15 * 60 * 1000 });
            artifacts.push({ tool: "nikto", dojoScanType: "Nikto Scan", filePath: outPath, format: "xml", target: url });
        }
        catch (err) {
            ctx.log.error({ err, url }, "scan: nikto failed for url");
        }
    }
    ctx.log.info({ urls: urls.length, artifacts: artifacts.length }, "scan: nikto complete");
    return artifacts;
}
//# sourceMappingURL=nikto.js.map