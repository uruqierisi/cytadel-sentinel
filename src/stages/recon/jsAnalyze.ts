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

  for (const jsUrl of files) {
    // Defensive re-gate before fetching the asset itself.
    if (!(await gate(ctx, jsUrl)).allowed) continue;
    let res: HttpResponse;
    try {
      res = await httpFn(jsUrl, { headers: ctx.auth.headerMap, maxBodyBytes: MAX_JS_BYTES });
    } catch (err) {
      ctx.log.debug({ err, jsUrl }, "recon: JS fetch failed (analysis)");
      continue;
    }
    if (res.status < 200 || res.status >= 400 || !res.body) continue;

    for (const url of extractEndpointCandidates(res.body, jsUrl)) {
      if (seen.has(url)) continue;
      seen.add(url);
      // EVERY extracted URL passes the scope gate before it is kept.
      if (!(await gate(ctx, url)).allowed) continue;
      candidates.push(getCandidate(url, "js"));
    }
  }

  ctx.log.info({ jsFiles: files.length, candidates: candidates.length }, "recon: JS analysis complete");
  return candidates;
}
