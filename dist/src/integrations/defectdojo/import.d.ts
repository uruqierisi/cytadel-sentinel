import type { RunContext } from "../../core/context.js";
import type { ScanResult } from "../../stages/scan/index.js";
/**
 * Import stage: push every native scan artifact into DefectDojo via its
 * import-scan endpoint (built-in per-tool parsers), then record the engagement
 * on the Run. DefectDojo owns storage/dedupe/triage from here.
 */
export interface ImportResult {
    productId: number;
    engagementId: number;
    importedTests: number;
}
export declare function runImport(ctx: RunContext, scan: ScanResult): Promise<ImportResult>;
