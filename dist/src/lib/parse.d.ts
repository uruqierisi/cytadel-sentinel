/** Split tool stdout into trimmed, non-empty lines. */
export declare function parseLines(stdout: string): string[];
/** Parse newline-delimited JSON, skipping blank/garbage lines defensively. */
export declare function parseJsonl<T = unknown>(stdout: string): T[];
/**
 * Merge multiple JSONL sources into one deduped stream of valid JSON lines.
 *
 * Used for partial capture: a killed tool's `-o` file may hold only the flushed
 * lines while its stdout (which we also captured) holds the tail. Merging both
 * and deduping keeps EVERY emitted finding, not just the flushed ones. Only
 * lines that parse as JSON are kept, so a truncated final line is dropped
 * cleanly and the result is safe to re-import.
 */
export declare function mergeJsonlLines(sources: string[]): string;
/** Best-effort parse of a possibly-single JSON document or JSONL. */
export declare function parseJsonLoose<T = unknown>(stdout: string): T[];
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
export declare function parseJsonObjects<T = unknown>(input: string): T[];
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
export declare function parseJsonArrayLoose<T = unknown>(input: string): T[];
