import type { RunContext } from "../../core/context.js";
import type { ScanResult } from "../scan/index.js";
import { type UnifiedFinding } from "./types.js";
/**
 * Normalize stage: read each native scan artifact, map to UnifiedFinding, dedupe
 * within the run (key = tool + templateId + host + matchedLocation), and persist
 * Finding rows. Destructive-class findings are marked NEVER_AUTO for the
 * verification layer.
 */
export interface NormalizeResult {
    findings: UnifiedFinding[];
    persisted: number;
}
export declare function runNormalize(ctx: RunContext, scan: ScanResult): Promise<NormalizeResult>;
