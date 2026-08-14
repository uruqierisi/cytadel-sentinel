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
