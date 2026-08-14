/** Split tool stdout into trimmed, non-empty lines. */
export function parseLines(stdout) {
    return stdout
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
}
/** Parse newline-delimited JSON, skipping blank/garbage lines defensively. */
export function parseJsonl(stdout) {
    const out = [];
    for (const line of parseLines(stdout)) {
        try {
            out.push(JSON.parse(line));
        }
        catch {
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
export function mergeJsonlLines(sources) {
    const seen = new Set();
    const out = [];
    for (const src of sources) {
        for (const line of src.split(/\r?\n/)) {
            const t = line.trim();
            if (t.length === 0)
                continue;
            try {
                JSON.parse(t);
            }
            catch {
                continue; // skip banners / truncated tail
            }
            if (seen.has(t))
                continue;
            seen.add(t);
            out.push(t);
        }
    }
    return out.join("\n");
}
/** Best-effort parse of a possibly-single JSON document or JSONL. */
export function parseJsonLoose(stdout) {
    const trimmed = stdout.trim();
    if (!trimmed)
        return [];
    try {
        const doc = JSON.parse(trimmed);
        return Array.isArray(doc) ? doc : [doc];
    }
    catch {
        return parseJsonl(trimmed);
    }
}
//# sourceMappingURL=parse.js.map