import { hostOf } from "../normalize/types.js";

/**
 * URL sanitization for discovered endpoints (gau / waybackurls / katana).
 *
 * Public archives return garbage that mangles into the target host, e.g.
 *   testasp.vulnweb.com:/www.amazon.com/dp/...
 *   testasp.vulnweb.com:/www.nfl.com/news/story/...
 * These have the TARGET as the authority (so they wrongly pass the scope gate)
 * but smuggle an EXTERNAL host into the path. Left unchecked they inflate the
 * asset list and make scanners crawl the whole internet.
 *
 * This module runs BEFORE the scope gate and:
 *   - drops any URL whose path/query embeds a scheme ("://"),
 *   - drops any URL whose path starts with a bare external host
 *     (www.<domain>, or any registrable domain that isn't in scope),
 *   - normalizes malformed "host:/path" (colon with empty port) -> "host/path",
 *   - dedupes.
 *
 * It never widens scope: the real scope gate still runs afterward on whatever
 * survives, with its audit semantics unchanged.
 */

/** Looks like a hostname label sequence ending in a TLD-ish suffix. */
const DOMAIN_RE = /^([a-z0-9-]+\.)+[a-z]{2,}$/i;

/** Trailing labels that are file extensions, not TLDs — so "sitemap.xml" is a path, not a host. */
const FILE_EXT = new Set([
  "html", "htm", "xhtml", "shtml", "asp", "aspx", "jsp", "jspx", "php", "php3", "php4", "php5",
  "cfm", "cgi", "pl", "do", "action", "js", "mjs", "cjs", "ts", "css", "scss", "less", "json",
  "xml", "rss", "atom", "txt", "md", "csv", "tsv", "yaml", "yml", "pdf", "doc", "docx", "xls",
  "xlsx", "ppt", "pptx", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "tiff",
  "zip", "gz", "tar", "rar", "7z", "woff", "woff2", "ttf", "eot", "otf", "map", "wasm", "mp4",
  "webm", "mp3", "wav", "avi", "bak", "old", "swf",
]);

export type SanitizeReason =
  | "kept"
  | "normalized"
  | "empty"
  | "unparseable"
  | "embedded-scheme"
  | "external-host";

export interface SanitizeOutcome {
  /** Normalized URL, or null if the entry was dropped. */
  url: string | null;
  reason: SanitizeReason;
}

interface ParsedUrl {
  scheme: string | null;
  host: string;
  /** null = no colon; "" = malformed empty port; else the port digits/text. */
  port: string | null;
  /** Everything after the authority: starts with "/", "?", "#", or is "". */
  tail: string;
}

function parse(raw: string): ParsedUrl | null {
  let rest = raw;
  let scheme: string | null = null;
  const m = rest.match(/^([a-z][a-z0-9+.-]*):\/\//i);
  if (m) {
    scheme = m[1]!.toLowerCase();
    rest = rest.slice(m[0].length);
  }
  if (rest.length === 0) return null;

  // Authority ends at the first '/', '?' or '#'.
  let end = rest.length;
  for (const ch of ["/", "?", "#"]) {
    const i = rest.indexOf(ch);
    if (i >= 0 && i < end) end = i;
  }
  const authority = rest.slice(0, end);
  const tail = rest.slice(end);
  if (authority.length === 0) return null;

  const colon = authority.indexOf(":");
  const host = (colon === -1 ? authority : authority.slice(0, colon)).toLowerCase();
  const port = colon === -1 ? null : authority.slice(colon + 1);
  if (host.length === 0) return null;

  return { scheme, host, port, tail };
}

/** Does a leading path segment look like an external (non-target) host? */
function looksLikeExternalHost(segment: string, isInScopeHost: (host: string) => boolean): boolean {
  const low = segment.toLowerCase();
  if (!DOMAIN_RE.test(low)) return false;
  const isWww = low.startsWith("www.");
  const lastLabel = low.slice(low.lastIndexOf(".") + 1);
  // "sitemap.xml" / "login.aspx" are paths, not hosts — unless clearly a www.* host.
  if (!isWww && FILE_EXT.has(lastLabel)) return false;
  // A segment that is itself in scope (e.g. an in-scope subdomain) is not "external".
  if (isInScopeHost(low)) return false;
  return true;
}

/**
 * Sanitize a single discovered URL. Returns the normalized URL (possibly
 * unchanged) or null with a reason when it should be dropped.
 */
export function sanitizeUrl(raw: string, isInScopeHost: (host: string) => boolean): SanitizeOutcome {
  const s = raw.trim();
  if (s.length === 0) return { url: null, reason: "empty" };

  const p = parse(s);
  if (!p) return { url: null, reason: "unparseable" };

  // Embedded scheme anywhere in the path/query => mangled external URL.
  if (p.tail.includes("://")) return { url: null, reason: "embedded-scheme" };

  // Normalize a malformed empty port ("host:/path" -> "host/path").
  let normalized = false;
  let port = p.port;
  if (port !== null && port.trim() === "") {
    port = null;
    normalized = true;
  }

  // Leading path segment that is a bare external host => drop.
  if (p.tail.startsWith("/")) {
    const firstSeg = p.tail.slice(1).split(/[/?#]/)[0] ?? "";
    if (firstSeg && looksLikeExternalHost(firstSeg, isInScopeHost)) {
      return { url: null, reason: "external-host" };
    }
  }

  const authority = port ? `${p.host}:${port}` : p.host;
  const url = (p.scheme ? `${p.scheme}://` : "") + authority + p.tail;
  return { url, reason: normalized ? "normalized" : "kept" };
}

export interface SanitizeStats {
  total: number;
  kept: number;
  normalized: number;
  droppedEmbeddedScheme: number;
  droppedExternalHost: number;
  droppedOther: number;
  duplicates: number;
}

/** Sanitize + dedupe a batch of discovered URLs. */
export function sanitizeDiscoveredUrls(
  raw: string[],
  isInScopeHost: (host: string) => boolean,
): { urls: string[]; stats: SanitizeStats } {
  const stats: SanitizeStats = {
    total: raw.length,
    kept: 0,
    normalized: 0,
    droppedEmbeddedScheme: 0,
    droppedExternalHost: 0,
    droppedOther: 0,
    duplicates: 0,
  };
  const seen = new Set<string>();
  const urls: string[] = [];

  for (const r of raw) {
    const res = sanitizeUrl(r, isInScopeHost);
    if (!res.url) {
      if (res.reason === "embedded-scheme") stats.droppedEmbeddedScheme++;
      else if (res.reason === "external-host") stats.droppedExternalHost++;
      else stats.droppedOther++;
      continue;
    }
    if (res.reason === "normalized") stats.normalized++;
    const key = res.url.toLowerCase();
    if (seen.has(key)) {
      stats.duplicates++;
      continue;
    }
    seen.add(key);
    urls.push(res.url);
    stats.kept++;
  }
  return { urls, stats };
}

/**
 * Cap the number of endpoints kept per host. Deterministic (input order). The
 * caller logs a notice for each truncated host.
 */
export function capEndpointsPerHost(
  urls: string[],
  cap: number,
): { kept: string[]; truncated: Map<string, number> } {
  const perHost = new Map<string, number>();
  const truncated = new Map<string, number>();
  const kept: string[] = [];

  for (const u of urls) {
    const host = hostOf(u);
    const n = perHost.get(host) ?? 0;
    if (n >= cap) {
      truncated.set(host, (truncated.get(host) ?? 0) + 1);
      continue;
    }
    perHost.set(host, n + 1);
    kept.push(u);
  }
  return { kept, truncated };
}
