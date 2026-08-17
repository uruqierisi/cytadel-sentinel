import { audit } from "../../lib/audit.js";
import { ensureRunDirs } from "../../lib/paths.js";
import { LIMITS } from "../../config/limits.js";
import { gate, type RunContext } from "../../core/context.js";
import type { ReconResult } from "../recon/index.js";
import type { ScanArtifact } from "./artifacts.js";
import { buildNucleiTargets } from "./targets.js";
import { paramSignature, planInjectionTargets } from "./params.js";
import { runNuclei } from "./nuclei.js";
import { runTestssl } from "./testssl.js";
import { runNikto } from "./nikto.js";
import { runRetire } from "./retire.js";
import { runDalfox } from "./dalfox.js";
import { runSqlmap } from "./sqlmap.js";

/**
 * Scan stage. Runs the active scanners over in-scope, alive web assets and
 * returns the native output artifacts (for DefectDojo import + normalize).
 *
 * Authenticated scanning: ctx.auth header lines are injected into every scanner
 * so testing goes past login.
 *
 * Destructive gate: destructive checks require BOTH scope.allow_destructive AND
 * the --allow-destructive CLI flag (ctx.allowDestructive). The decision is
 * audit-logged. Phase 1 keeps intrusive nuclei tags excluded regardless.
 */
export interface ScanResult {
  artifacts: ScanArtifact[];
}

/** Derive host:port for TLS testing from an alive web URL. */
function hostPort(url: string): string | null {
  try {
    const u = new URL(url);
    const port = u.port ? u.port : u.protocol === "https:" ? "443" : "80";
    return `${u.hostname}:${port}`;
  } catch {
    return null;
  }
}

export async function runScan(ctx: RunContext, recon: ReconResult): Promise<ScanResult> {
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
  const urls: string[] = [];
  const tlsHosts = new Set<string>();
  for (const t of recon.webTargets) {
    const decision = await gate(ctx, t.url);
    if (!decision.allowed) continue;
    urls.push(t.url);
    const hp = hostPort(t.url);
    if (hp) tlsHosts.add(hp);
  }

  const artifacts: ScanArtifact[] = [];

  // nuclei: feed a REDUCED, deduped set (base URLs + unique query-stripped paths),
  // NOT every crawled param URL. This is the lever that lets nuclei FINISH instead
  // of being SIGTERM-killed at its timeout.
  const nucleiTargets = buildNucleiTargets(urls, recon.endpoints, LIMITS.nuclei.maxTargets);
  ctx.bus.stageProgress(
    "scan",
    `nuclei over ${nucleiTargets.length} base/unique-path target(s) (from ${recon.endpoints.length} endpoints)`,
    true,
  );
  const nucleiArtifact = await runNuclei(ctx, nucleiTargets);
  if (nucleiArtifact) artifacts.push(nucleiArtifact);

  // nikto per URL.
  ctx.bus.stageProgress("scan", `nikto over ${urls.length} URL(s)`, true);
  artifacts.push(...(await runNikto(ctx, urls)));

  // testssl per host:port.
  ctx.bus.stageProgress("scan", `testssl over ${tlsHosts.size} host(s)`, true);
  artifacts.push(...(await runTestssl(ctx, [...tlsHosts])));

  // retire.js over discovered JS assets.
  ctx.bus.stageProgress("scan", `retire.js over ${recon.jsUrls.length} JS asset(s)`, true);
  const retireArtifact = await runRetire(ctx, recon.jsUrls);
  if (retireArtifact) artifacts.push(retireArtifact);

  // Active injection (dalfox XSS + sqlmap SQLi) — STRICTLY behind the
  // destructive gate. When closed (default) we skip silently; the DESTRUCTIVE_GATE
  // audit event above already records the decision, and the report notes it.
  if (ctx.allowDestructive) {
    // Seed param URLs bypass recon discovery (SPAs/APIs katana/gau can't crawl,
    // e.g. Juice Shop /rest/products/search?q=). They are scope-gated but their
    // VALUES are PRESERVED verbatim — a user who seeds ?q=apple means "fuzz
    // apple": sqlmap's boolean/time-based blind needs a value that returns real
    // results to stabilize, and normalizing to ?q=1 breaks detection. (Discovered
    // params keep normalization — their risk is archived attack payloads; seeds
    // are user-authored and intentional.) Dedupe still collapses same-signature
    // seeds via planInjectionTargets, keeping the first real value. Seeds go
    // FIRST so they always survive the maxInjectionTargets cap.
    const seedCandidates = ctx.scope.seed_param_urls ?? [];
    const gatedSeeds: string[] = [];
    for (const u of seedCandidates) {
      if ((await gate(ctx, u)).allowed) gatedSeeds.push(u);
    }

    // Collapse the merged param URLs to distinct injection SIGNATURES exactly
    // ONCE, then hand the SAME capped list to both tools. dalfox and sqlmap must
    // run over the identical ~7-25 deduped signatures — never the raw hundreds —
    // or they burn their budget before reaching the interesting ones.
    const { targets: injectionTargets, fromSeeds, fromDiscovery } = planInjectionTargets(
      gatedSeeds,
      recon.paramUrls,
      LIMITS.maxInjectionTargets,
    );

    ctx.bus.stageProgress(
      "scan",
      `active injection over ${injectionTargets.length} deduped signature(s) ` +
        `(${fromSeeds} seed · ${fromDiscovery} discovered)`,
      false,
    );
    // Log the FINAL signature list (path + param names) both tools will fuzz, so
    // we can confirm the real injectable endpoints are actually reached.
    const signatureLabels = injectionTargets.map((u) => paramSignature(u) ?? u);
    ctx.log.info(
      {
        seedParamUrls: seedCandidates.length,
        gatedSeeds: gatedSeeds.length,
        rawParamUrls: recon.paramUrls.length,
        injectionTargets: injectionTargets.length,
        fromSeeds,
        fromDiscovery,
        cap: LIMITS.maxInjectionTargets,
        signatures: signatureLabels,
      },
      "scan: active-injection targets (shared by dalfox + sqlmap)",
    );
    ctx.bus.stageProgress("scan", `injection signatures: ${signatureLabels.join(" · ")}`, true);
    const dalfoxArtifact = await runDalfox(ctx, injectionTargets);
    if (dalfoxArtifact) artifacts.push(dalfoxArtifact);
    const sqlmapArtifact = await runSqlmap(ctx, injectionTargets);
    if (sqlmapArtifact) artifacts.push(sqlmapArtifact);
  } else {
    ctx.log.info(
      { paramUrls: recon.paramUrls.length },
      "scan: active injection (dalfox/sqlmap) skipped — destructive gate closed",
    );
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
