import type { RunContext } from "../../core/context.js";
import type { ScanArtifact } from "./artifacts.js";
/**
 * nuclei — templated web/cve/misconfig/exposure/tech checks over alive in-scope
 * URLs.
 *
 * Targets are fed via stdin (never a shell string). Auth headers are injected so
 * scanning goes past login. Rate limited per scope, with per-request timeout /
 * retry / concurrency caps so a scan cannot run unbounded.
 *
 * PARTIAL CAPTURE: nuclei writes incrementally to `-o nuclei.jsonl`. If nuclei is
 * killed at the timeout (SIGTERM), we STILL read whatever landed on disk (or the
 * captured stdout) and hand it to Normalize — valid findings are never discarded.
 */
export declare function runNuclei(ctx: RunContext, urls: string[]): Promise<ScanArtifact | null>;
