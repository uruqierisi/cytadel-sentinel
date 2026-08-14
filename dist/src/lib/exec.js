import { execFile } from "node:child_process";
import { logger } from "./logger.js";
const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;
const DEFAULT_MAX_BUFFER = 64 * 1024 * 1024;
/** Reject any arg that isn't a plain string — guards against undefined/objects leaking in. */
function assertStringArgs(file, args) {
    if (typeof file !== "string" || file.length === 0) {
        throw new TypeError("exec: `file` must be a non-empty string");
    }
    for (const [i, a] of args.entries()) {
        if (typeof a !== "string") {
            throw new TypeError(`exec: arg[${i}] must be a string, got ${typeof a}`);
        }
    }
}
/**
 * Run an external binary safely.
 *
 * @param file Executable name or absolute path (NOT a shell command line).
 * @param args Argument array. Each element is passed verbatim; never parsed by a shell.
 */
export function run(file, args = [], opts = {}) {
    assertStringArgs(file, args);
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxBuffer = opts.maxBufferBytes ?? DEFAULT_MAX_BUFFER;
    const startedAt = Date.now();
    return new Promise((resolve, reject) => {
        const child = execFile(file, args, {
            cwd: opts.cwd,
            env: opts.env ? { ...process.env, ...opts.env } : process.env,
            timeout: timeoutMs,
            maxBuffer,
            windowsHide: true,
            // shell is intentionally omitted -> defaults to false. DO NOT enable.
        }, (error, stdout, stderr) => {
            const durationMs = Date.now() - startedAt;
            const code = child.exitCode;
            const signal = child.signalCode;
            const timedOut = Boolean(error && error.code === "ETIMEDOUT");
            const result = {
                file,
                args,
                code,
                signal,
                stdout: stdout ?? "",
                stderr: stderr ?? "",
                durationMs,
                timedOut,
            };
            logger.debug({ file, argc: args.length, code, signal, durationMs, timedOut }, "exec finished");
            if (error && !timedOut && opts.allowNonZeroExit && typeof code === "number") {
                // Non-zero exit that the caller expects (scanner "found something").
                resolve(result);
                return;
            }
            if (error && timedOut && opts.tolerateTimeout) {
                // Killed at the timeout — return whatever was captured. The caller
                // reads the partial output rather than discarding valid findings.
                logger.warn({ file, argc: args.length, durationMs }, "exec timed out — returning PARTIAL result (not discarded)");
                resolve(result);
                return;
            }
            if (error) {
                const err = error;
                err.result = result;
                err.message =
                    `exec failed: ${file} (code=${code} signal=${signal}` +
                        `${timedOut ? " timedOut" : ""}): ${err.message}`;
                reject(err);
                return;
            }
            resolve(result);
        });
        if (opts.input !== undefined && child.stdin) {
            child.stdin.end(opts.input);
        }
    });
}
/** Resolve the version string of a tool (best-effort; returns "unknown" on failure). */
export async function toolVersion(file, versionArgs = ["--version"]) {
    try {
        const { stdout, stderr } = await run(file, versionArgs, {
            timeoutMs: 15_000,
            allowNonZeroExit: true,
        });
        const out = (stdout || stderr).trim();
        return out.split("\n")[0]?.trim() || "unknown";
    }
    catch {
        return "unknown";
    }
}
/** True if a binary is resolvable/executable on PATH. */
export async function toolExists(file, versionArgs = ["--version"]) {
    try {
        await run(file, versionArgs, { timeoutMs: 15_000, allowNonZeroExit: true });
        return true;
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=exec.js.map