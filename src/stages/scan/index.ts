import { audit } from "../../lib/audit.js";
import { ensureRunDirs, rawDir } from "../../lib/paths.js";
import { authSecretValues, scrubTree, findSecretLeaks } from "../../lib/scrub.js";
import { LIMITS } from "../../config/limits.js";
import { evaluateProductionGate } from "../../core/governance.js";
import { gate, type RunContext } from "../../core/context.js";
import type { ReconResult } from "../recon/index.js";
import type { ScanArtifact } from "./artifacts.js";
import { buildNucleiTargets } from "./targets.js";
import { dedupeCandidates, countBySource, candidateSignature, getCandidate, type InjectionCandidate } from "./candidates.js";
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
  // WP6 production safety: against a production environment, destructive
  // injection requires an explicit --i-understand-production confirmation.
  const prodGate = evaluateProductionGate(ctx.scope, ctx.allowDestructive, ctx.confirmProduction);
  if (ctx.allowDestructive && ctx.scope.environment === "production") {
    await audit({
      runId: ctx.runId,
      actor: ctx.actor,
      action: "ENVIRONMENT_GATE",
      scopeHash: ctx.scopeHash,
      detail: { environment: ctx.scope.environment, confirmProduction: ctx.confirmProduction, blocked: prodGate.blocked, reason: prodGate.reason },
    });
  }
  const injectionAllowed = ctx.allowDestructive && !prodGate.blocked;

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
  if (injectionAllowed) {
    // Seed param URLs (scope) are scope-gated with their VALUES PRESERVED — a
    // user who seeds ?q=apple means "fuzz apple". Seeds go FIRST so they always
    // survive the cap. They merge with the method-aware candidates recon already
    // discovered (discovery / JS analysis / OpenAPI / GraphQL — each gated).
    const seedUrls = ctx.scope.seed_param_urls ?? [];
    const seedCandidates: InjectionCandidate[] = [];
    for (const u of seedUrls) {
      if ((await gate(ctx, u)).allowed) seedCandidates.push(getCandidate(u, "seed"));
    }

    const merged = [...seedCandidates, ...recon.injectionCandidates];
    const injectionTargets = dedupeCandidates(merged, LIMITS.maxInjectionTargets);
    const bySource = countBySource(injectionTargets);

    // WP4: record what was actually fuzzed (params tested, GET vs POST bodies).
    const getCount = injectionTargets.filter((c) => c.method === "GET").length;
    const postCount = injectionTargets.length - getCount;
    ctx.coverage.params.tested = injectionTargets.length;
    ctx.coverage.candidatesBySource = bySource;
    ctx.coverage.injection = { get: getCount, post: postCount, ran: injectionTargets.length > 0 };
    // The dedupe cap silently drops candidates beyond the limit — surface it.
    if (merged.length > injectionTargets.length) {
      ctx.coverage.caps.push({
        name: "injection-target cap",
        cap: LIMITS.maxInjectionTargets,
        dropped: merged.length - injectionTargets.length,
      });
    }

    ctx.bus.stageProgress(
      "scan",
      `active injection over ${injectionTargets.length} candidate(s) ` +
        `(seed ${bySource.seed} · discovery ${bySource.discovery} · js ${bySource.js} · ` +
        `openapi ${bySource.openapi} · graphql ${bySource.graphql})`,
      false,
    );
    const labels = injectionTargets.map((c) => candidateSignature(c));
    ctx.log.info(
      { total: injectionTargets.length, bySource, cap: LIMITS.maxInjectionTargets, signatures: labels },
      "scan: active-injection candidates (shared by dalfox + sqlmap)",
    );
    ctx.bus.stageProgress("scan", `injection signatures: ${labels.join(" · ")}`, true);

    const dalfoxArtifact = await runDalfox(ctx, injectionTargets);
    if (dalfoxArtifact) artifacts.push(dalfoxArtifact);
    const sqlmapArtifact = await runSqlmap(ctx, injectionTargets);
    if (sqlmapArtifact) artifacts.push(sqlmapArtifact);
  } else {
    // WP4/WP6: injection didn't run — record WHY (destructive gate closed OR the
    // production safety gate blocked it) as a coverage limitation.
    const skippedReason = prodGate.blocked
      ? prodGate.reason
      : "destructive gate closed (scope allow_destructive:false and/or no --allow-destructive)";
    ctx.coverage.injection = { get: 0, post: 0, ran: false, skippedReason };
    if (prodGate.blocked) {
      ctx.bus.stageProgress("scan", `active injection SKIPPED — ${skippedReason}`, false);
    }
    ctx.log.info(
      { paramUrls: recon.paramUrls.length, skippedReason },
      "scan: active injection (dalfox/sqlmap) skipped",
    );
  }

  // SECURITY: several tools echo their full command line (incl. -H
  // "Authorization: Bearer <JWT>" / --cookie <value>) into on-disk output
  // (sqlmap target.txt / log / session.sqlite). Scrub the session secret(s) from
  // the ENTIRE raw tree now that all tools have finished — the plaintext token
  // must never remain in a raw artifact.
  await scrubRawSecrets(ctx);

  ctx.log.info({ artifacts: artifacts.length }, "scan: complete");
  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "STAGE_COMPLETE",
    detail: { stage: "scan", artifacts: artifacts.length },
  });
  return { artifacts };
}

/** Mask session secrets across the run's raw artifacts, then verify none remain. */
async function scrubRawSecrets(ctx: RunContext): Promise<void> {
  const secrets = authSecretValues(ctx.auth);
  if (secrets.length === 0) return;
  const dir = rawDir(ctx.runId);
  const result = await scrubTree(dir, secrets);
  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "SECRET_SCRUB",
    detail: { scope: "raw", filesModified: result.filesModified, occurrences: result.occurrences },
  });
  ctx.log.info(
    { filesModified: result.filesModified, occurrences: result.occurrences },
    "scan: scrubbed auth secrets from raw artifacts",
  );

  // Verify the scrub actually removed everything — a residual leak is loud.
  const leaks = await findSecretLeaks(dir, secrets);
  if (leaks.length > 0) {
    ctx.log.error({ leaks }, "scan: SECRET LEAK — auth material still present in raw artifacts after scrub");
    await audit({
      runId: ctx.runId,
      actor: ctx.actor,
      action: "SECRET_LEAK",
      detail: { scope: "raw", files: leaks },
    });
  }
}
