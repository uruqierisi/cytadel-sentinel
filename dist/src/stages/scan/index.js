import { audit } from "../../lib/audit.js";
import { ensureRunDirs } from "../../lib/paths.js";
import { gate } from "../../core/context.js";
import { runNuclei } from "./nuclei.js";
import { runTestssl } from "./testssl.js";
import { runNikto } from "./nikto.js";
import { runRetire } from "./retire.js";
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
    const nucleiArtifact = await runNuclei(ctx, urls);
    if (nucleiArtifact)
        artifacts.push(nucleiArtifact);
    // nikto per URL.
    artifacts.push(...(await runNikto(ctx, urls)));
    // testssl per host:port.
    artifacts.push(...(await runTestssl(ctx, [...tlsHosts])));
    // retire.js over discovered JS assets.
    const retireArtifact = await runRetire(ctx, recon.jsUrls);
    if (retireArtifact)
        artifacts.push(retireArtifact);
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