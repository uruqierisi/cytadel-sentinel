import { prisma } from "../../db/client.js";
import { audit } from "../../lib/audit.js";
import { gate, gateMany, type RunContext } from "../../core/context.js";
import { evaluateScope } from "../../config/inScope.js";
import { LIMITS } from "../../config/limits.js";
import { subfinder, httpx, katana, gau, waybackurls, naabu, type HttpxResult } from "./tools.js";
import { sanitizeDiscoveredUrls, capEndpointsPerHost } from "./sanitize.js";

/**
 * Recon stage.
 *
 * Passive subdomain enumeration -> scope gate -> liveness/fingerprint ->
 * URL/endpoint discovery -> light port context. EVERY discovered asset passes
 * through the scope gate before it is kept or touched. Results are persisted as
 * Asset rows and the alive web targets are handed to the scan stage.
 */

export interface ReconResult {
  /** Alive web targets (in-scope) with fingerprints — input to the scan stage. */
  webTargets: HttpxResult[];
  /** In-scope JS asset URLs — fed to retire.js. */
  jsUrls: string[];
  /** In-scope URLs carrying query params — fed to active-injection tools (gated). */
  paramUrls: string[];
  /** In-scope non-JS endpoints (capped) — reduced to base/unique paths for nuclei. */
  endpoints: string[];
  /** Count of every asset persisted this run. */
  assetCount: number;
}

const JS_URL = /\.js(\?|$)/i;
const HAS_PARAM = /\?[^#]*=[^#]*/;

/** Seed apex/base domains and seed hosts from the scope. */
function seedTargets(ctx: RunContext): { domains: string[]; hosts: string[] } {
  const domains = new Set<string>();
  const hosts = new Set<string>();
  for (const d of ctx.scope.in_scope.domains) {
    domains.add(d.startsWith("*.") ? d.slice(2) : d);
    if (!d.startsWith("*.")) hosts.add(d);
  }
  for (const u of ctx.scope.in_scope.urls) {
    try {
      hosts.add(new URL(u).hostname);
    } catch {
      /* schema validated; ignore */
    }
  }
  return { domains: [...domains], hosts: [...hosts] };
}

async function persistHost(ctx: RunContext, r: HttpxResult, ports: number[]): Promise<void> {
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

async function persistSimple(
  ctx: RunContext,
  type: "SUBDOMAIN" | "URL" | "ENDPOINT" | "JS_ASSET",
  value: string,
): Promise<void> {
  await prisma.asset.upsert({
    where: { runId_type_value: { runId: ctx.runId, type, value } },
    create: { runId: ctx.runId, type, value, inScope: true },
    update: {},
  });
}

export async function runRecon(ctx: RunContext): Promise<ReconResult> {
  ctx.log.info("recon: starting");
  await audit({ runId: ctx.runId, actor: ctx.actor, action: "STAGE_START", detail: { stage: "recon" } });

  const { domains, hosts: seedHosts } = seedTargets(ctx);

  // 1) Passive subdomain enumeration.
  const discovered = new Set<string>(seedHosts);
  for (const domain of domains) {
    for (const sub of await subfinder(ctx, domain)) discovered.add(sub);
  }

  // 2) Scope gate — hard filter every discovered host BEFORE any active probe.
  const inScopeHosts = await gateMany(ctx, [...discovered]);
  for (const h of inScopeHosts) await persistSimple(ctx, "SUBDOMAIN", h);
  ctx.log.info({ discovered: discovered.size, inScope: inScopeHosts.length }, "recon: hosts gated");
  // Collapse the per-target SCOPE_ACCEPT decisions into one reporter line.
  ctx.bus.scopeSummary(inScopeHosts.length, discovered.size);
  if (inScopeHosts.length < discovered.size) {
    ctx.bus.stageProgress(
      "recon",
      `${discovered.size - inScopeHosts.length} host(s) rejected by scope gate`,
      true,
    );
  }

  // 3) Liveness + fingerprint (in-scope only).
  const alive = await httpx(ctx, inScopeHosts);
  ctx.bus.stageProgress("recon", `${alive.length} host(s) alive`, true);
  for (const r of alive) {
    ctx.bus.stageProgress("recon", `${r.url} [${r.statusCode ?? "?"}] ${r.title ?? ""}`.trim(), true);
  }

  // 4) Light port context per alive host + persist host assets.
  const webTargets: HttpxResult[] = [];
  for (const r of alive) {
    // Re-gate the resolved URL host defensively (httpx may canonicalize).
    const decision = await gate(ctx, r.url || r.host);
    if (!decision.allowed) continue;
    const ports = await naabu(ctx, r.host || decision.host || "");
    await persistHost(ctx, r, ports);
    for (const p of ports) {
      await persistSimple(ctx, "URL", `${r.host}:${p}`).catch(() => undefined);
    }
    webTargets.push(r);
  }

  // 5) URL/endpoint + JS discovery over alive web targets.
  const rawFound: string[] = [];
  for (const t of webTargets) {
    rawFound.push(...(await katana(ctx, t.url)));
    rawFound.push(...(await gau(ctx, t.host)));
    rawFound.push(...(await waybackurls(ctx, t.host)));
  }

  // 5a) SANITIZE before the scope gate: drop mangled external URLs (embedded
  // scheme / bare external host in path), normalize "host:/path", dedupe. This
  // stops garbage archive entries from masquerading as in-scope assets.
  const isInScopeHost = (host: string) => evaluateScope(ctx.scope, host).allowed;
  const { urls: cleaned, stats } = sanitizeDiscoveredUrls(rawFound, isInScopeHost);
  ctx.log.info({ ...stats }, "recon: url sanitize");
  ctx.bus.stageProgress(
    "recon",
    `sanitized URLs: ${stats.kept} kept · ${stats.droppedExternalHost} external · ` +
      `${stats.droppedEmbeddedScheme} embedded-scheme · ${stats.duplicates} dup (of ${stats.total})`,
    true,
  );

  // 5b) Scope gate (semantics + audit unchanged) on the cleaned URLs.
  const gated: string[] = [];
  for (const u of cleaned) {
    const decision = await gate(ctx, u);
    if (decision.allowed) gated.push(u);
  }

  // 5c) Cap per host — but in SEPARATE buckets. JS/static assets must NOT be
  // trimmed by the HTML-endpoint cap, or retire.js is left with nothing (JS=0).
  const jsAll = gated.filter((u) => JS_URL.test(u));
  const nonJs = gated.filter((u) => !JS_URL.test(u));

  const { kept: cappedNonJs, truncated } = capEndpointsPerHost(nonJs, LIMITS.maxEndpointsPerHost);
  for (const [host, dropped] of truncated) {
    ctx.log.warn({ host, dropped, cap: LIMITS.maxEndpointsPerHost }, "recon: endpoint cap reached");
    ctx.bus.stageProgress(
      "recon",
      `capped ${host} at ${LIMITS.maxEndpointsPerHost} endpoints (+${dropped} dropped)`,
      false,
    );
  }
  const { kept: cappedJs, truncated: jsTruncated } = capEndpointsPerHost(jsAll, LIMITS.maxJsAssetsPerHost);
  for (const [host, dropped] of jsTruncated) {
    ctx.log.warn({ host, dropped, cap: LIMITS.maxJsAssetsPerHost }, "recon: JS asset cap reached");
  }

  const endpointSet = new Set<string>([...cappedNonJs, ...cappedJs]);
  const jsSet = new Set<string>(cappedJs);
  const paramSet = new Set<string>(cappedNonJs.filter((u) => HAS_PARAM.test(u)));

  for (const u of endpointSet) await persistSimple(ctx, "ENDPOINT", u);
  for (const j of jsSet) await persistSimple(ctx, "JS_ASSET", j);

  const assetCount = await prisma.asset.count({ where: { runId: ctx.runId } });
  ctx.log.info(
    { web: webTargets.length, endpoints: cappedNonJs.length, js: jsSet.size, assetCount },
    "recon: complete",
  );
  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "STAGE_COMPLETE",
    detail: { stage: "recon", assetCount, webTargets: webTargets.length, js: jsSet.size },
  });

  return {
    webTargets,
    jsUrls: [...jsSet],
    paramUrls: [...paramSet],
    endpoints: cappedNonJs,
    assetCount,
  };
}
