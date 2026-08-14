import { audit } from "../../lib/audit.js";
import { ensureRunDirs } from "../../lib/paths.js";
import { gate } from "../../core/context.js";
import { runNuclei } from "./nuclei.js";
import { runTestssl } from "./testssl.js";
import { runNikto } from "./nikto.js";
import { runRetire } from "./retire.js";
import { runDalfox } from "./dalfox.js";
import { runSqlmap } from "./sqlmap.js";
/** Derive host:port for TLS testing from an alive web URL. */
function hostPort(url) {
    try {
        const u = new URL(url);
        const port = u.port ? u.port : u.protocol === "https:" ? "443" : "80";
        return `${u.hostname}:${port}`;
    }
    catch {
        return null;
    }
}
export async function runScan(ctx, recon) {
    ctx.log.info({ webTargets: recon.webTargets.length }, "scan: starting");
    await audit({ runId: ctx.runId, actor: ctx.actor, action: "STAGE_START", detail: { stage: "scan" } });
    await audit({
        runId: ctx.runId,
        actor: ctx.actor,
        action: "DESTRUCTIVE_GATE",
        scopeHash: ctx.scopeHash,
        detail: {
            allowDestructive: ctx.allowDestructive,
            scopeAllows: ctx.scope.allow_destructive,
            note: "destructive checks require both scope flag and CLI --allow-destructive",
        },
    });
    await ensureRunDirs(ctx.runId);
    // Build in-scope target lists (defensively re-gated).
    const urls = [];
    const tlsHosts = new Set();
    for (const t of recon.webTargets) {
        const decision = await gate(ctx, t.url);
        if (!decision.allowed)
            continue;
        urls.push(t.url);
        const hp = hostPort(t.url);
        if (hp)
            tlsHosts.add(hp);
    }
    const artifacts = [];
    // nuclei over all URLs (one aggregate artifact).
    ctx.bus.stageProgress("scan", `nuclei over ${urls.length} URL(s)`, true);
    const nucleiArtifact = await runNuclei(ctx, urls);
    if (nucleiArtifact)
        artifacts.push(nucleiArtifact);
    // nikto per URL.
    ctx.bus.stageProgress("scan", `nikto over ${urls.length} URL(s)`, true);
    artifacts.push(...(await runNikto(ctx, urls)));
    // testssl per host:port.
    ctx.bus.stageProgress("scan", `testssl over ${tlsHosts.size} host(s)`, true);
    artifacts.push(...(await runTestssl(ctx, [...tlsHosts])));
    // retire.js over discovered JS assets.
    ctx.bus.stageProgress("scan", `retire.js over ${recon.jsUrls.length} JS asset(s)`, true);
    const retireArtifact = await runRetire(ctx, recon.jsUrls);
    if (retireArtifact)
        artifacts.push(retireArtifact);
    // Active injection (dalfox XSS + sqlmap SQLi) — STRICTLY behind the
    // destructive gate. When closed (default) we skip silently; the DESTRUCTIVE_GATE
    // audit event above already records the decision, and the report notes it.
    if (ctx.allowDestructive) {
        ctx.bus.stageProgress("scan", `active injection over ${recon.paramUrls.length} param URL(s)`, false);
        const dalfoxArtifact = await runDalfox(ctx, recon.paramUrls);
        if (dalfoxArtifact)
            artifacts.push(dalfoxArtifact);
        const sqlmapArtifact = await runSqlmap(ctx, recon.paramUrls);
        if (sqlmapArtifact)
            artifacts.push(sqlmapArtifact);
    }
    else {
        ctx.log.info({ paramUrls: recon.paramUrls.length }, "scan: active injection (dalfox/sqlmap) skipped — destructive gate closed");
    }
    ctx.log.info({ artifacts: artifacts.length }, "scan: complete");
    await audit({
        runId: ctx.runId,
        actor: ctx.actor,
        action: "STAGE_COMPLETE",
        detail: { stage: "scan", artifacts: artifacts.length },
    });
    return { artifacts };
}
//# sourceMappingURL=index.js.map