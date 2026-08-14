import { writeFile } from "node:fs/promises";
import path from "node:path";
import { run, toolExists } from "../../lib/exec.js";
import { httpRequest } from "../../lib/http.js";
import { audit } from "../../lib/audit.js";
import { rawDir, jsDir } from "../../lib/paths.js";
import { gate } from "../../core/context.js";
/**
 * retire.js — outdated/vulnerable JS libraries.
 *
 * retire scans a local directory, so we first DOWNLOAD each in-scope JS asset
 * (re-gated for safety) with the undici client, save it under raw/js/, then run
 * retire over that directory. DefectDojo's "Retire.js Scan" parser consumes the
 * JSON output.
 */
export async function runRetire(ctx, jsUrls) {
    if (jsUrls.length === 0)
        return null;
    if (!(await toolExists("retire", ["--version"]))) {
        ctx.log.warn("scan: retire.js not installed — skipping");
        return null;
    }
    const dir = jsDir(ctx.runId);
    let downloaded = 0;
    for (const url of jsUrls) {
        const decision = await gate(ctx, url); // re-gate: never fetch out of scope
        if (!decision.allowed)
            continue;
        try {
            const res = await httpRequest(url, { headers: ctx.auth.headerMap, maxBodyBytes: 5 * 1024 * 1024 });
            if (res.status >= 200 && res.status < 300 && res.body.length > 0) {
                const safeName = url.replace(/[^a-z0-9.-]+/gi, "_").slice(0, 120) + ".js";
                await writeFile(path.join(dir, safeName), res.body, "utf8");
                downloaded++;
            }
        }
        catch (err) {
            ctx.log.debug({ err, url }, "scan: retire JS download failed");
        }
    }
    if (downloaded === 0) {
        ctx.log.warn("scan: retire.js — no JS assets downloaded, skipping");
        return null;
    }
    const outPath = path.join(rawDir(ctx.runId), "retirejs.json");
    await audit({
        runId: ctx.runId,
        actor: ctx.actor,
        action: "TOOL_EXEC",
        scopeHash: ctx.scopeHash,
        detail: { tool: "retirejs", stage: "scan", downloaded },
    });
    try {
        await run("retire", ["--path", dir, "--outputformat", "json", "--outputpath", outPath, "--exitwith", "0"], { allowNonZeroExit: true, timeoutMs: 5 * 60 * 1000 });
        ctx.log.info({ outPath, downloaded }, "scan: retire.js complete");
        return { tool: "retirejs", dojoScanType: "Retire.js Scan", filePath: outPath, format: "json", target: "aggregate" };
    }
    catch (err) {
        ctx.log.error({ err }, "scan: retire.js failed");
        return null;
    }
}
//# sourceMappingURL=retire.js.map