/**
 * Collapse param URLs by injection SIGNATURE = (origin + path + sorted param
 * NAMES), ignoring param VALUES. `showforum.asp?id=1` and `showforum.asp?id=2`
 * are the same injection test, so we keep ONE representative (with concrete
 * values so the tool has a working request to fuzz).
 *
 * This is the main lever that turns 183 param URLs into a handful of distinct
 * tests for sqlmap/dalfox.
 */

function withScheme(u: string): string {
  return u.includes("://") ? u : "https://" + u;
}

/** Injection signature, or null if the URL has no query parameters. */
export function paramSignature(url: string): string | null {
  try {
    const x = new URL(withScheme(url));
    if (x.protocol !== "http:" && x.protocol !== "https:") return null;
    const names = [...x.searchParams.keys()].map((n) => n.toLowerCase()).sort();
    if (names.length === 0) return null;
    return `${x.protocol}//${x.host}${x.pathname}?${names.join("&")}`;
  } catch {
    return null;
  }
}

/**
 * Dedupe param URLs by signature and cap the count. Keeps the first-seen URL for
 * each signature (it carries real values). URLs without params are dropped.
 */
export function dedupeParamSignatures(urls: string[], cap: number): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const u of urls) {
    const sig = paramSignature(u);
    if (sig === null || seen.has(sig)) continue;
    seen.add(sig);
    out.push(u);
    if (out.length >= Math.max(1, cap)) break;
  }
  return out;
}
