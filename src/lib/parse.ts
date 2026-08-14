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
