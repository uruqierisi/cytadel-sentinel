import { audit } from "../../lib/audit.js";
import { ensureRunDirs } from "../../lib/paths.js";
import { gate, type RunContext } from "../../core/context.js";
import type { ReconResult } from "../recon/index.js";
import type { ScanArtifact } from "./artifacts.js";
import { runNuclei } from "./nuclei.js";
import { runTestssl } from "./testssl.js";
import { runNikto } from "./nikto.js";
import { runRetire } from "./retire.js";

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

  // nuclei over all URLs (one aggregate artifact).
  ctx.bus.stageProgress("scan", `nuclei over ${urls.length} URL(s)`, true);
  const nucleiArtifact = await runNuclei(ctx, urls);
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

  ctx.log.info({ artifacts: artifacts.length }, "scan: complete");
  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "STAGE_COMPLETE",
    detail: { stage: "scan", artifacts: artifacts.length },
  });
  return { artifacts };
}
