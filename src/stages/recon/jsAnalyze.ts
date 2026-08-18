import { httpRequest, type HttpResponse } from "../../lib/http.js";
import { gate, type RunContext } from "../../core/context.js";
import { getCandidate, type InjectionCandidate } from "../scan/candidates.js";

/**
 * JS bundle analysis (WP2, task 1).
 *
 * SPAs (React/Angular) never expose their API routes to katana/gau — the routes
 * live inside the compiled JS bundle. We fetch each in-scope .js asset and
 * statically scan it for endpoint references (fetch/axios/XHR/route literals),
 * extract the API paths + query params, resolve them against the bundle origin,
 * and (after scope-gating) hand them to the injection candidate set.
 *
 * Extraction is a pure function (unit-testable, no network). The fetch+gate
 * wrapper is separate; the `httpFn` seam lets tests inject a transport.
 */

export type HttpFn = (url: string, opts?: Parameters<typeof httpRequest>[1]) => Promise<HttpResponse>;

const MAX_JS_FILES = intFromEnv("SENTINEL_JS_ANALYZE_MAX_FILES", 30);
const MAX_JS_BYTES = intFromEnv("SENTINEL_JS_ANALYZE_MAX_BYTES", 4 * 1024 * 1024);

function intFromEnv(name: string, fallback: number): number {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

// Patterns that reference an endpoint. Each captures the URL/path string.
const PATTERNS: readonly RegExp[] = [
  /fetch\(\s*[`'"]([^`'"]+)[`'"]/gi, // fetch("…")
  /axios(?:\.\w+)?\(\s*[`'"]([^`'"]+)[`'"]/gi, // axios("…") / axios.get("…") / axios.post("…")
  /\.open\(\s*[`'"](?:GET|POST|PUT|PATCH|DELETE)[`'"]\s*,\s*[`'"]([^`'"]+)[`'"]/gi, // xhr.open("POST","…")
  /(?:url|path|endpoint|baseURL)\s*:\s*[`'"]([^`'"]+)[`'"]/gi, // { url: "…" } config objects
  /[`'"](\/(?:rest|api|graphql|v\d+|auth|users?|products?|orders?|search)\/?[^`'"\s]*)[`'"]/gi, // API-root literals
  /[`'"](\/[^`'"\s]*\?[^`'"\s]*=[^`'"\s]*)[`'"]/gi, // any "/path?key=…" literal
];

/** Set empty-valued query params to a benign default so the request works. */
function fillEmptyQuery(u: URL, def = "1"): void {
  for (const key of [...u.searchParams.keys()]) {
    if (u.searchParams.get(key) === "") u.searchParams.set(key, def);
  }
}

/**
 * Extract absolute, query-bearing endpoint URLs referenced by a JS bundle.
 * Relative paths resolve against `baseUrl`. Only http(s) URLs with at least one
 * query parameter (i.e. injectable) are returned; duplicates are removed.
 */
export function extractEndpointCandidates(js: string, baseUrl: string): string[] {
  const out = new Set<string>();
  for (const re of PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(js)) !== null) {
      const raw = m[1];
      if (!raw || raw.length > 2048) continue;
      let u: URL;
      try {
        u = new URL(raw, baseUrl);
      } catch {
        continue;
      }
      if (u.protocol !== "http:" && u.protocol !== "https:") continue;
      if ([...u.searchParams.keys()].length === 0) continue; // need a param to inject
      fillEmptyQuery(u);
      out.add(u.toString());
    }
  }
  return [...out];
}

/**
 * Extract <script src="…"> references from an HTML page, resolved absolute.
 * Handles double/single-quoted and UNQUOTED src values, and relative paths
 * (src="main.js") as well as rooted ones (src="/main.js").
 */
export function extractScriptSrcs(html: string, baseUrl: string): string[] {
  const out = new Set<string>();
  // Group 1 = double-quoted, 2 = single-quoted, 3 = unquoted.
  const re = /<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const raw = m[1] ?? m[2] ?? m[3];
    if (!raw) continue;
    try {
      const u = new URL(raw, baseUrl);
      if (u.protocol === "http:" || u.protocol === "https:") out.add(u.toString());
    } catch {
      /* skip malformed src */
    }
  }
  return [...out];
}

const JS_LIKE = /\.m?js(\?|$)/i;

/**
 * SPA bootstrap: fetch each origin's base HTML, extract <script src> bundles
 * (main.js, polyfills.js, runtime.js, …) — which katana/gau never surface — and
 * return the in-scope JS asset URLs. Logs per origin so a live run shows exactly
 * what was found and why a source is empty.
 */
export async function collectScriptAssets(
  ctx: RunContext,
  origins: string[],
  httpFn: HttpFn = httpRequest,
): Promise<{ assets: string[]; notes: string[] }> {
  const assets = new Set<string>();
  const notes: string[] = [];
  for (const origin of origins) {
    const htmlUrl = origin.endsWith("/") ? origin : origin + "/";
    if (!(await gate(ctx, htmlUrl)).allowed) continue;
    let res: HttpResponse;
    try {
      res = await httpFn(htmlUrl, { headers: ctx.auth.headerMap, maxBodyBytes: MAX_JS_BYTES, maxRedirections: 3 });
    } catch (err) {
      ctx.log.warn({ htmlUrl, error: (err as Error).message }, "recon: FETCH base HTML FAILED (JS discovery)");
      notes.push(`JS: base HTML fetch failed for ${htmlUrl}: ${(err as Error).message}`);
      continue;
    }
    // Distinct FETCH-RESULT line (separate from the gate SCOPE_ACCEPT).
    ctx.log.info(
      { htmlUrl, status: res.status, bodyLen: res.body.length, contentType: res.headers["content-type"] },
      "recon: FETCH base HTML",
    );
    if (res.status < 200 || res.status >= 400 || !res.body) {
      notes.push(`JS: base HTML ${htmlUrl} returned ${res.status} (len ${res.body.length})`);
      continue;
    }
    const allSrcs = extractScriptSrcs(res.body, htmlUrl);
    const jsSrcs = allSrcs.filter((s) => JS_LIKE.test(new URL(s).pathname));
    // Show the RAW matches so a live run reveals exactly what the HTML contained.
    ctx.log.info({ htmlUrl, scriptSrcs: allSrcs, jsSrcs }, "recon: <script src> matches");
    let kept = 0;
    for (const s of jsSrcs) {
      if ((await gate(ctx, s)).allowed) {
        assets.add(s);
        kept++;
      }
    }
    ctx.log.info({ htmlUrl, scriptTags: allSrcs.length, jsSrcs: jsSrcs.length, inScopeJs: kept }, "recon: base HTML script assets");
    if (allSrcs.length === 0) notes.push(`JS: no <script src> found in ${htmlUrl} (body ${res.body.length} bytes)`);
    else if (jsSrcs.length === 0) notes.push(`JS: <script src> found but none matched *.js in ${htmlUrl}`);
  }
  return { assets: [...assets], notes };
}

/**
 * Fetch each in-scope JS asset, extract endpoints, scope-gate them, and return
 * method-aware GET injection candidates (source "js").
 */
export async function analyzeJsAssets(
  ctx: RunContext,
  jsUrls: string[],
  httpFn: HttpFn = httpRequest,
): Promise<InjectionCandidate[]> {
  const candidates: InjectionCandidate[] = [];
  const seen = new Set<string>();
  const files = jsUrls.slice(0, MAX_JS_FILES);
  let fetched = 0;

  for (const jsUrl of files) {
    // Defensive re-gate before fetching the asset itself.
    if (!(await gate(ctx, jsUrl)).allowed) continue;
    let res: HttpResponse;
    try {
      res = await httpFn(jsUrl, { headers: ctx.auth.headerMap, maxBodyBytes: MAX_JS_BYTES, maxRedirections: 3 });
    } catch (err) {
      ctx.log.warn({ jsUrl, error: (err as Error).message }, "recon: FETCH JS asset FAILED");
      continue;
    }
    // Distinct FETCH-RESULT line.
    ctx.log.info(
      { jsUrl, status: res.status, bodyLen: res.body.length, contentType: res.headers["content-type"] },
      "recon: FETCH JS asset",
    );
    if (res.status < 200 || res.status >= 400 || !res.body) continue;
    fetched++;
    const before = candidates.length;
    for (const url of extractEndpointCandidates(res.body, jsUrl)) {
      if (seen.has(url)) continue;
      seen.add(url);
      // EVERY extracted URL passes the scope gate before it is kept.
      if (!(await gate(ctx, url)).allowed) continue;
      candidates.push(getCandidate(url, "js"));
    }
    ctx.log.info({ jsUrl, endpoints: candidates.length - before }, "recon: JS asset analysed");
  }

  ctx.log.info({ jsAssets: files.length, fetched, candidates: candidates.length }, "recon: JS analysis complete");
  return candidates;
}
