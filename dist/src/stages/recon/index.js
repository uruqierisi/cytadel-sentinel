import { prisma } from "../../db/client.js";
import { audit } from "../../lib/audit.js";
import { gate, gateMany } from "../../core/context.js";
import { subfinder, httpx, katana, gau, waybackurls, naabu } from "./tools.js";
const JS_URL = /\.js(\?|$)/i;
/** Seed apex/base domains and seed hosts from the scope. */
function seedTargets(ctx) {
    const domains = new Set();
    const hosts = new Set();
    for (const d of ctx.scope.in_scope.domains) {
        domains.add(d.startsWith("*.") ? d.slice(2) : d);
        if (!d.startsWith("*."))
            hosts.add(d);
    }
    for (const u of ctx.scope.in_scope.urls) {
        try {
            hosts.add(new URL(u).hostname);
        }
        catch {
            /* schema validated; ignore */
        }
    }
    return { domains: [...domains], hosts: [...hosts] };
}
async function persistHost(ctx, r, ports) {
    await prisma.asset.upsert({
        where: { runId_type_value: { runId: ctx.runId, type: "HOST", value: r.host || r.url } },
        create: {
            runId: ctx.runId,
            type: "HOST",
            value: r.host || r.url,
            inScope: true,
            alive: true,
            statusCode: r.statusCode ?? undefined,
            title: r.title ?? undefined,
            server: r.server ?? undefined,
            tech: r.tech,
            ports,
        },
        update: {
            alive: true,
            statusCode: r.statusCode ?? undefined,
            title: r.title ?? undefined,
            server: r.server ?? undefined,
            tech: r.tech,
            ports,
        },
    });
}
async function persistSimple(ctx, type, value) {
    await prisma.asset.upsert({
        where: { runId_type_value: { runId: ctx.runId, type, value } },
        create: { runId: ctx.runId, type, value, inScope: true },
        update: {},
    });
}
export async function runRecon(ctx) {
    ctx.log.info("recon: starting");
    await audit({ runId: ctx.runId, actor: ctx.actor, action: "STAGE_START", detail: { stage: "recon" } });
    const { domains, hosts: seedHosts } = seedTargets(ctx);
    // 1) Passive subdomain enumeration.
    const discovered = new Set(seedHosts);
    for (const domain of domains) {
        for (const sub of await subfinder(ctx, domain))
            discovered.add(sub);
    }
    // 2) Scope gate — hard filter every discovered host BEFORE any active probe.
    const inScopeHosts = await gateMany(ctx, [...discovered]);
    for (const h of inScopeHosts)
        await persistSimple(ctx, "SUBDOMAIN", h);
    ctx.log.info({ discovered: discovered.size, inScope: inScopeHosts.length }, "recon: hosts gated");
    // Collapse the per-target SCOPE_ACCEPT decisions into one reporter line.
    ctx.bus.scopeSummary(inScopeHosts.length, discovered.size);
    if (inScopeHosts.length < discovered.size) {
        ctx.bus.stageProgress("recon", `${discovered.size - inScopeHosts.length} host(s) rejected by scope gate`, true);
    }
    // 3) Liveness + fingerprint (in-scope only).
    const alive = await httpx(ctx, inScopeHosts);
    ctx.bus.stageProgress("recon", `${alive.length} host(s) alive`, true);
    for (const r of alive) {
        ctx.bus.stageProgress("recon", `${r.url} [${r.statusCode ?? "?"}] ${r.title ?? ""}`.trim(), true);
    }
    // 4) Light port context per alive host + persist host assets.
    const webTargets = [];
    for (const r of alive) {
        // Re-gate the resolved URL host defensively (httpx may canonicalize).
        const decision = await gate(ctx, r.url || r.host);
        if (!decision.allowed)
            continue;
        const ports = await naabu(ctx, r.host || decision.host || "");
        await persistHost(ctx, r, ports);
        for (const p of ports) {
            await persistSimple(ctx, "URL", `${r.host}:${p}`).catch(() => undefined);
        }
        webTargets.push(r);
    }
    // 5) URL/endpoint + JS discovery over alive web targets.
    const urlSet = new Set();
    const jsSet = new Set();
    for (const t of webTargets) {
        const found = [
            ...(await katana(ctx, t.url)),
            ...(await gau(ctx, t.host)),
            ...(await waybackurls(ctx, t.host)),
        ];
        for (const u of found) {
            const decision = await gate(ctx, u);
            if (!decision.allowed)
                continue;
            urlSet.add(u);
            if (JS_URL.test(u))
                jsSet.add(u);
        }
    }
    for (const u of urlSet)
        await persistSimple(ctx, "ENDPOINT", u);
    for (const j of jsSet)
        await persistSimple(ctx, "JS_ASSET", j);
    const assetCount = await prisma.asset.count({ where: { runId: ctx.runId } });
    ctx.log.info({ web: webTargets.length, endpoints: urlSet.size, js: jsSet.size, assetCount }, "recon: complete");
    await audit({
        runId: ctx.runId,
        actor: ctx.actor,
        action: "STAGE_COMPLETE",
        detail: { stage: "recon", assetCount, webTargets: webTargets.length },
    });
    return { webTargets, jsUrls: [...jsSet], assetCount };
}
//# sourceMappingURL=index.js.map