/**
 * Param-value hygiene for discovered URLs.
 *
 * gau / waybackurls return HISTORICAL URLs from public archives. Many already
 * carry OTHER people's attack traffic baked into the param VALUES, e.g. (decoded):
 *   /Login.asp?RetURL=/showforum.asp?id=1&XNYy=3116 AND 1=1 UNION ALL SELECT ...
 *   EXEC xp_cmdshell('cat ../../../etc/passwd')#
 *
 * If kept, these become bogus "discovered params" and sqlmap/dalfox burn their
 * whole time budget fuzzing junk instead of the real params (showforum.asp?id=,
 * Search.asp?tfSearch=). Two defences here, applied BEFORE signature dedupe:
 *
 *   1. DROP any URL whose param values already contain injection/attack syntax
 *      (SQL, XSS, command-injection, traversal). A discovered value should be a
 *      normal value, not an attack string.
 *   2. NORMALIZE surviving values to a neutral placeholder ("1") so the injection
 *      SIGNATURE is (path + param names) and the representative request handed to
 *      the scanners is CLEAN (id=1), never a payload-laden historical one.
 *
 * This does NOT touch the scope gate or audit trail — it only shapes which param
 * URLs are considered injection candidates.
 */

/** Neutral value used for every param of a cleaned representative. */
export const NEUTRAL_PARAM_VALUE = "1";

/** decodeURIComponent that tolerates '+' as space and never throws. */
function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}

/**
 * Patterns that mark a param value as an ATTACK string rather than a real value.
 * Tuned to avoid firing on ordinary values: multi-token SQL, tag/handler XSS,
 * shell/traversal markers — not bare single words.
 */
const PAYLOAD_PATTERNS: readonly RegExp[] = [
  // --- SQL injection ---
  // (Bare "select ... from" is intentionally NOT matched — it fires on ordinary
  // search phrases. Real SQLi shows up as UNION SELECT / information_schema /
  // boolean tautologies / stacked queries below.)
  /union\s+(all\s+)?select/i,
  /information_schema/i,
  /\bxp_cmdshell\b/i,
  /\b(and|or)\b\s+\d+\s*=\s*\d+/i, // AND 1=1 / OR 1=1
  /['"]\s*(or|and)\s+['"]?\w+\s*=/i, // ' or 1=  / " and a=
  /(?:^|[\s'")])--(?:\s|$)/, // SQL line comment "-- "
  /\/\*.*?\*\//, // /**/ inline comment
  /;\s*(drop|insert|update|delete|select|shutdown|exec)\b/i,
  /\b(sleep|benchmark|pg_sleep)\s*\(/i,
  /waitfor\s+delay/i,
  /\bload_file\s*\(/i,
  /\binto\s+(out|dump)file\b/i,
  /\bchar\s*\(\s*\d+/i,
  /\bconcat\s*\(/i,
  /0x[0-9a-f]{8,}/i, // long hex blob
  // --- XSS / JS ---
  /<\/?script/i,
  /<svg/i,
  /<img[^>]*on\w+\s*=/i,
  /\bon(error|load|mouseover|focus|click)\s*=/i,
  /javascript:/i,
  /\balert\s*\(/i,
  /\beval\s*\(/i,
  /document\.(cookie|domain|location|write)/i,
  // --- Command injection / path traversal ---
  /\.\.[\/\\]/, // ../ or ..\
  /\/etc\/passwd/i,
  /\bcat\s+\/?\w+\//i,
  /\$\(/, // $( ... )
  /`[^`]*`/, // backtick command substitution
  /%00/, // null byte (even undecoded)
];

/**
 * True if any param VALUE in the URL looks like an injection payload. The query
 * is decoded first (archives store payloads URL-encoded), and both the whole
 * decoded query and each decoded value are tested so patterns that span
 * multiple params still fire.
 */
export function hasInjectionPayload(url: string): boolean {
  const qIdx = url.indexOf("?");
  if (qIdx < 0) return false;
  const hashIdx = url.indexOf("#", qIdx);
  const query = url.slice(qIdx + 1, hashIdx >= 0 ? hashIdx : undefined);
  if (query.length === 0) return false;

  const haystacks: string[] = [safeDecode(query)];
  for (const pair of query.split("&")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    haystacks.push(safeDecode(pair.slice(eq + 1)));
  }
  return haystacks.some((h) => PAYLOAD_PATTERNS.some((re) => re.test(h)));
}

/**
 * Rewrite every query VALUE to the neutral placeholder, preserving the scheme,
 * host, path, param NAMES and their order, and dropping any fragment. The result
 * is a clean, working representative request for a scanner to fuzz.
 */
export function normalizeParamValues(raw: string, placeholder: string = NEUTRAL_PARAM_VALUE): string {
  const hashIdx = raw.indexOf("#");
  const noFrag = hashIdx >= 0 ? raw.slice(0, hashIdx) : raw;
  const qIdx = noFrag.indexOf("?");
  if (qIdx < 0) return noFrag;

  const base = noFrag.slice(0, qIdx);
  const query = noFrag.slice(qIdx + 1);
  const names: string[] = [];
  for (const pair of query.split("&")) {
    if (pair === "") continue;
    const eq = pair.indexOf("=");
    const name = eq < 0 ? pair : pair.slice(0, eq);
    if (name === "") continue;
    names.push(name);
  }
  if (names.length === 0) return base;
  return `${base}?${names.map((n) => `${n}=${placeholder}`).join("&")}`;
}

export interface ParamCleanStats {
  total: number;
  droppedPayload: number;
  kept: number;
  duplicates: number;
}

/**
 * Drop payload-laden param URLs, normalize the survivors to clean representative
 * values, and dedupe the normalized strings. Runs BEFORE dedupeParamSignatures,
 * so the representative that reaches sqlmap/dalfox is guaranteed clean.
 */
export function cleanParamUrls(
  urls: string[],
  placeholder: string = NEUTRAL_PARAM_VALUE,
): { urls: string[]; stats: ParamCleanStats } {
  const stats: ParamCleanStats = { total: urls.length, droppedPayload: 0, kept: 0, duplicates: 0 };
  const seen = new Set<string>();
  const out: string[] = [];
  for (const u of urls) {
    if (hasInjectionPayload(u)) {
      stats.droppedPayload++;
      continue;
    }
    const norm = normalizeParamValues(u, placeholder);
    const key = norm.toLowerCase();
    if (seen.has(key)) {
      stats.duplicates++;
      continue;
    }
    seen.add(key);
    out.push(norm);
    stats.kept++;
  }
  return { urls: out, stats };
}
