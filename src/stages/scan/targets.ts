/**
 * Build nuclei's target set.
 *
 * nuclei templates match on hosts / base URLs and unique PATHS — feeding every
 * crawled param URL (e.g. 302 `?id=1..302` variants) just multiplies work for no
 * extra coverage and blows the timeout. So we feed:
 *   1. the alive base origins (host roots), always included first, and
 *   2. unique base+path URLs with the query string stripped (id=1 / id=2 / … all
 *      collapse to one `/showforum.asp`),
 * deduped and capped. This is the primary lever that lets a single-host scan
 * finish in minutes instead of being SIGTERM-killed.
 */

function withScheme(u: string): string {
  return u.includes("://") ? u : "https://" + u;
}

/** scheme://host[:port]/ — the host root. */
function toOrigin(u: string): string | null {
  try {
    const x = new URL(withScheme(u));
    if (x.protocol !== "http:" && x.protocol !== "https:") return null;
    return `${x.protocol}//${x.host}/`;
  } catch {
    return null;
  }
}

/** scheme://host[:port]/path — query and fragment removed. */
function toBasePath(u: string): string | null {
  try {
    const x = new URL(withScheme(u));
    if (x.protocol !== "http:" && x.protocol !== "https:") return null;
    const p = x.pathname && x.pathname.length > 0 ? x.pathname : "/";
    return `${x.protocol}//${x.host}${p}`;
  } catch {
    return null;
  }
}

/**
 * @param baseUrls alive web target URLs (host roots from httpx)
 * @param endpoints discovered in-scope endpoints (query-bearing or not)
 * @param cap maximum targets to feed nuclei
 */
export function buildNucleiTargets(baseUrls: string[], endpoints: string[], cap: number): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const add = (u: string | null): void => {
    if (!u) return;
    const key = u.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push(u);
  };

  // Host roots first so they're never trimmed by the cap.
  for (const b of baseUrls) add(toOrigin(b));
  // Then unique query-stripped paths.
  for (const e of endpoints) add(toBasePath(e));

  return out.slice(0, Math.max(1, cap));
}
