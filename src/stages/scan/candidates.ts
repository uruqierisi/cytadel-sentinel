/**
 * Method-aware injection candidate model (WP2).
 *
 * Phase 1 modelled injection targets as bare GET query URLs (string[]). Modern
 * apps expose REST/GraphQL over POST/PUT bodies too, so a candidate now carries
 * an HTTP method and (for non-GET) a body template. sqlmap/dalfox test the query
 * OR the body accordingly.
 *
 * Every candidate URL is scope-gated by the producer BEFORE it becomes a
 * candidate — this module is pure shaping/dedupe and does no network or gating.
 */

export type HttpMethodU = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
export type CandidateSource = "discovery" | "seed" | "js" | "openapi" | "graphql";

export interface InjectionCandidate {
  /** Full URL (includes the query for GET candidates). */
  url: string;
  method: HttpMethodU;
  /** Request body template for non-GET candidates (form- or JSON-encoded), else null. */
  body: string | null;
  /** Content-type for the body, else null. */
  contentType: string | null;
  /** Parameter names to fuzz (query and/or body). */
  paramNames: string[];
  /** Where the candidate came from (for coverage attribution). */
  source: CandidateSource;
}

function withScheme(u: string): string {
  return u.includes("://") ? u : "https://" + u;
}

/**
 * Injection signature: method + origin + path + sorted param NAMES + whether it
 * carries a body. Values are ignored so ?id=1 and ?id=2 collapse to one test.
 */
export function candidateSignature(c: InjectionCandidate): string {
  try {
    const u = new URL(withScheme(c.url));
    const queryNames = [...u.searchParams.keys()].map((n) => n.toLowerCase());
    const names = [...new Set([...queryNames, ...c.paramNames.map((n) => n.toLowerCase())])].sort();
    return `${c.method} ${u.protocol}//${u.host}${u.pathname}?${names.join("&")}${c.body != null ? " +body" : ""}`;
  } catch {
    return `${c.method} ${c.url}`;
  }
}

/**
 * Dedupe candidates by signature (keep first-seen — it carries a concrete
 * request) and cap the count. Order is preserved so callers can prioritise
 * (e.g. seeds first) by ordering the input.
 */
export function dedupeCandidates(cands: InjectionCandidate[], cap: number): InjectionCandidate[] {
  const seen = new Set<string>();
  const out: InjectionCandidate[] = [];
  for (const c of cands) {
    const sig = candidateSignature(c);
    if (seen.has(sig)) continue;
    seen.add(sig);
    out.push(c);
    if (out.length >= Math.max(1, cap)) break;
  }
  return out;
}

/** Count candidates by source (for the coverage/attribution log). */
export function countBySource(cands: InjectionCandidate[]): Record<CandidateSource, number> {
  const counts: Record<CandidateSource, number> = { discovery: 0, seed: 0, js: 0, openapi: 0, graphql: 0 };
  for (const c of cands) counts[c.source]++;
  return counts;
}

/** Build a GET candidate from a param URL (discovery / seed). */
export function getCandidate(url: string, source: CandidateSource): InjectionCandidate {
  let paramNames: string[] = [];
  try {
    paramNames = [...new URL(withScheme(url)).searchParams.keys()];
  } catch {
    /* leave empty */
  }
  return { url, method: "GET", body: null, contentType: null, paramNames, source };
}
