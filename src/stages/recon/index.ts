import { prisma } from "../../db/client.js";
import { audit } from "../../lib/audit.js";
import { gate, gateMany, type RunContext } from "../../core/context.js";
import { evaluateScope } from "../../config/inScope.js";
import { LIMITS } from "../../config/limits.js";
import { subfinder, httpx, katana, gau, waybackurls, naabu, type HttpxResult } from "./tools.js";
import { sanitizeDiscoveredUrls, capEndpointsPerHost } from "./sanitize.js";
import { cleanParamUrls } from "./paramClean.js";
import { paramSignature } from "../scan/params.js";
import { analyzeJsAssets } from "./jsAnalyze.js";
import { discoverOpenApi } from "./openapi.js";
import { discoverGraphql } from "./graphql.js";
import { getCandidate, countBySource, type InjectionCandidate } from "../scan/candidates.js";

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
  /**
   * Method-aware injection candidates from ALL discovery sources (discovery /
   * JS analysis / OpenAPI / GraphQL), each already scope-gated. Fed to the
   * active-injection tools alongside scope seeds.
   */
  injectionCandidates: InjectionCandidate[];
  /** Coverage notes from GraphQL discovery (e.g. introspection disabled). */
  graphqlNotes: string[];
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

  // Injection candidates: keep only param URLs whose VALUES are real values, not
  // archived attack payloads (wayback poisoning), then normalize each to a CLEAN
  // representative (id=1) BEFORE signature dedupe downstream. This keeps
  // sqlmap/dalfox pointed at the real params instead of junk.
  const paramCandidates = cappedNonJs.filter((u) => HAS_PARAM.test(u));
  const { urls: cleanParams, stats: paramStats } = cleanParamUrls(paramCandidates);
  if (paramStats.droppedPayload > 0) {
    ctx.log.warn({ ...paramStats }, "recon: dropped payload-laden (wayback-poisoned) param URLs");
    ctx.bus.stageProgress(
      "recon",
      `dropped ${paramStats.droppedPayload} payload-laden param URL(s) · ${paramStats.kept} clean param signature(s)`,
      true,
    );
  }
  const paramSet = new Set<string>(cleanParams);
  // Log the final param signatures (path + names) so we can confirm the real
  // injectable endpoints (showforum.asp?id=, Search.asp?tfSearch=) are present.
  ctx.log.info(
    { paramSignatures: [...paramSet].map((u) => paramSignature(u) ?? u) },
    "recon: clean injection param signatures",
  );

  for (const u of endpointSet) await persistSimple(ctx, "ENDPOINT", u);
  for (const j of jsSet) await persistSimple(ctx, "JS_ASSET", j);

  // --- WP2: SPA/API endpoint discovery (JS analysis, OpenAPI, GraphQL). ---
  // These reach modern client-side/API routes that katana/gau can't crawl. Every
  // produced URL is scope-gated inside each analyzer before it is kept.
  const origins = collectOrigins(ctx, webTargets);
  const discoveryCandidates = [...paramSet].map((u) => getCandidate(u, "discovery"));
  const jsCandidates = await analyzeJsAssets(ctx, [...jsSet]);
  const openApiCandidates = await discoverOpenApi(ctx, origins, ctx.scope.openapi_urls ?? []);
  const graphql = await discoverGraphql(ctx, origins, cappedNonJs);
  const injectionCandidates = [
    ...discoveryCandidates,
    ...jsCandidates,
    ...openApiCandidates,
    ...graphql.candidates,
  ];
  const bySource = countBySource(injectionCandidates);
  ctx.log.info({ bySource, total: injectionCandidates.length }, "recon: injection candidates by source");
  ctx.bus.stageProgress(
    "recon",
    `injection candidates: ${injectionCandidates.length} ` +
      `(discovery ${bySource.discovery} · js ${bySource.js} · openapi ${bySource.openapi} · graphql ${bySource.graphql})`,
    false,
  );

  const assetCount = await prisma.asset.count({ where: { runId: ctx.runId } });
  ctx.log.info(
    { web: webTargets.length, endpoints: cappedNonJs.length, js: jsSet.size, assetCount },
    "recon: complete",
  );
  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "STAGE_COMPLETE",
    detail: { stage: "recon", assetCount, webTargets: webTargets.length, js: jsSet.size, injectionCandidates: injectionCandidates.length },
  });

  return {
    webTargets,
    jsUrls: [...jsSet],
    paramUrls: [...paramSet],
    endpoints: cappedNonJs,
    injectionCandidates,
    graphqlNotes: graphql.notes,
    assetCount,
  };
}

/** Distinct scheme://host origins to probe for specs / graphql (from alive targets + scope urls). */
function collectOrigins(ctx: RunContext, webTargets: HttpxResult[]): string[] {
  const origins = new Set<string>();
  const add = (raw: string): void => {
    try {
      const u = new URL(raw);
      origins.add(`${u.protocol}//${u.host}`);
    } catch {
      /* ignore */
    }
  };
  for (const t of webTargets) add(t.url);
  for (const u of ctx.scope.in_scope.urls) add(u);
  return [...origins];
}
