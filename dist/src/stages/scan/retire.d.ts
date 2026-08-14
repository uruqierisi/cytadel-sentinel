import { type RunContext } from "../../core/context.js";
import type { ScanArtifact } from "./artifacts.js";
/**
 * retire.js — outdated/vulnerable JS libraries.
 *
 * retire scans a local directory, so we first DOWNLOAD each in-scope JS asset
 * (re-gated for safety) with the undici client, save it under raw/js/, then run
 * retire over that directory. DefectDojo's "Retire.js Scan" parser consumes the
 * JSON output.
 */
export declare function runRetire(ctx: RunContext, jsUrls: string[]): Promise<ScanArtifact | null>;
