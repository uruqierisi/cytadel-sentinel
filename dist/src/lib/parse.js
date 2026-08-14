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