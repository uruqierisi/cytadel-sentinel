/** Split tool stdout into trimmed, non-empty lines. */
export function parseLines(stdout: string): string[] {
  return stdout
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

/** Parse newline-delimited JSON, skipping blank/garbage lines defensively. */
export function parseJsonl<T = unknown>(stdout: string): T[] {
  const out: T[] = [];
  for (const line of parseLines(stdout)) {
    try {
      out.push(JSON.parse(line) as T);
    } catch {
      // Tools occasionally interleave banners/progress on stdout; skip non-JSON.
    }
  }
  return out;
}

/**
 * Merge multiple JSONL sources into one deduped stream of valid JSON lines.
 *
 * Used for partial capture: a killed tool's `-o` file may hold only the flushed
 * lines while its stdout (which we also captured) holds the tail. Merging both
 * and deduping keeps EVERY emitted finding, not just the flushed ones. Only
 * lines that parse as JSON are kept, so a truncated final line is dropped
 * cleanly and the result is safe to re-import.
 */
export function mergeJsonlLines(sources: string[]): string {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const src of sources) {
    for (const line of src.split(/\r?\n/)) {
      const t = line.trim();
      if (t.length === 0) continue;
      try {
        JSON.parse(t);
      } catch {
        continue; // skip banners / truncated tail
      }
      if (seen.has(t)) continue;
      seen.add(t);
      out.push(t);
    }
  }
  return out.join("\n");
}

/** Best-effort parse of a possibly-single JSON document or JSONL. */
export function parseJsonLoose<T = unknown>(stdout: string): T[] {
  const trimmed = stdout.trim();
  if (!trimmed) return [];
  try {
    const doc = JSON.parse(trimmed);
    return Array.isArray(doc) ? (doc as T[]) : [doc as T];
  } catch {
    return parseJsonl<T>(trimmed);
  }
}

/**
 * Extract every COMPLETE top-level `{...}` object from a string, ignoring any
 * surrounding array brackets and any truncated trailing object.
 *
 * This scans brace depth while respecting JSON strings/escapes, so braces inside
 * string values don't confuse it and nested objects/arrays are handled. A tool
 * killed mid-stream leaves its final object unterminated (depth never returns to
 * 0) — that object is simply dropped, and every complete object emitted before
 * the cut is returned. This is the robust core of partial-capture parsing for
 * JSON-array output formats (e.g. `dalfox --format json`).
 */
export function parseJsonObjects<T = unknown>(input: string): T[] {
  const out: T[] = [];
  let depth = 0;
  let start = -1;
  let inStr = false;
  let esc = false;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') {
      inStr = true;
    } else if (ch === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === "}") {
      if (depth > 0) {
        depth--;
        if (depth === 0 && start >= 0) {
          try {
            out.push(JSON.parse(input.slice(start, i + 1)) as T);
          } catch {
            // A malformed complete-looking block is skipped, not fatal.
          }
          start = -1;
        }
      }
    }
  }
  return out;
}

/**
 * Parse a JSON ARRAY that may be UNTERMINATED because the emitting tool was
 * killed mid-write (SIGTERM at a timeout). Strategy, in order:
 *   1. Strict parse — a complete array or single object.
 *   2. Repair a truncated array: drop any trailing comma/whitespace and append
 *      the missing "]", then parse. Recovers the common case where the array's
 *      objects are all complete and only the closing bracket is missing.
 *   3. Object-by-object extraction — the robust fallback that also recovers when
 *      the cut landed in the MIDDLE of the final object.
 *
 * Any complete objects emitted before the cut MUST survive. Returns [] only when
 * there is genuinely nothing parseable.
 */
export function parseJsonArrayLoose<T = unknown>(input: string): T[] {
  const trimmed = input.trim();
  if (!trimmed) return [];

  // 1) Strict.
  try {
    const doc = JSON.parse(trimmed);
    return Array.isArray(doc) ? (doc as T[]) : [doc as T];
  } catch {
    /* fall through */
  }

  // 2) Repair a truncated array by closing it.
  if (trimmed.startsWith("[")) {
    const repaired = trimmed.replace(/,?\s*$/, "") + "]";
    try {
      const doc = JSON.parse(repaired);
      if (Array.isArray(doc)) return doc as T[];
    } catch {
      /* fall through */
    }
  }

  // 3) Object-by-object (recovers a mid-object truncation too).
  return parseJsonObjects<T>(trimmed);
}
