/** Split tool stdout into trimmed, non-empty lines. */
export declare function parseLines(stdout: string): string[];
/** Parse newline-delimited JSON, skipping blank/garbage lines defensively. */
export declare function parseJsonl<T = unknown>(stdout: string): T[];
/** Best-effort parse of a possibly-single JSON document or JSONL. */
export declare function parseJsonLoose<T = unknown>(stdout: string): T[];
