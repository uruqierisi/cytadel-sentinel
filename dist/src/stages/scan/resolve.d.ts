/**
 * Resolve scanners that setup.sh may install EITHER on PATH (apt/gem) OR as a
 * git checkout under tools/. Returns the executable + any leading args, or null
 * if the tool is unavailable.
 */
export interface ResolvedTool {
    file: string;
    baseArgs: string[];
}
export declare function resolveNikto(): Promise<ResolvedTool | null>;
export declare function resolveTestssl(): Promise<ResolvedTool | null>;
/** dalfox (XSS) — active injection, destructive gate only. Installed via `go install`. */
export declare function resolveDalfox(): Promise<ResolvedTool | null>;
/** sqlmap (SQLi) — active injection, destructive gate only. PATH or tools/sqlmap checkout. */
export declare function resolveSqlmap(): Promise<ResolvedTool | null>;
