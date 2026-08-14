/**
 * SAFE process runner.
 *
 * NON-NEGOTIABLE RULE: target-controlled data (URLs, params, reflected values,
 * discovered hostnames) is untrusted. This module ONLY ever spawns via
 * `execFile` with an argument ARRAY. There is deliberately no code path that
 * accepts a concatenated shell string, and `shell` is never enabled — so no
 * shell metacharacter in a target can ever be interpreted.
 *
 * Do not add a `shell: true` option here. If you think you need one, you don't.
 */
export interface ExecOptions {
    /** Working directory for the child process. */
    cwd?: string;
    /** Extra environment variables merged over process.env. */
    env?: Record<string, string>;
    /** Hard timeout in milliseconds. Default 10 minutes. */
    timeoutMs?: number;
    /** Max stdout/stderr buffer in bytes. Default 64 MiB (scan output is large). */
    maxBufferBytes?: number;
    /** stdin to feed the process (e.g. a newline-delimited target list). */
    input?: string;
    /** If true, a non-zero exit code does NOT reject (many scanners exit 1 on "findings"). */
    allowNonZeroExit?: boolean;
}
export interface ExecResult {
    file: string;
    args: string[];
    code: number | null;
    signal: NodeJS.Signals | null;
    stdout: string;
    stderr: string;
    durationMs: number;
    timedOut: boolean;
}
/**
 * Run an external binary safely.
 *
 * @param file Executable name or absolute path (NOT a shell command line).
 * @param args Argument array. Each element is passed verbatim; never parsed by a shell.
 */
export declare function run(file: string, args?: string[], opts?: ExecOptions): Promise<ExecResult>;
/** Resolve the version string of a tool (best-effort; returns "unknown" on failure). */
export declare function toolVersion(file: string, versionArgs?: string[]): Promise<string>;
/** True if a binary is resolvable/executable on PATH. */
export declare function toolExists(file: string, versionArgs?: string[]): Promise<boolean>;
