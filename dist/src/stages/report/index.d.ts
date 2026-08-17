import { type Severity } from "../normalize/types.js";
import type { RunContext } from "../../core/context.js";
/**
 * Report stage. Renders a Cytadel-branded HTML + JSON report under
 * reports/<run-id>/ from the LOCAL normalized finding table — the exact same
 * set the CLI counts and that was imported to DefectDojo. Reading back from
 * DefectDojo here previously caused a divergence (CLI showed N, report.json 0)
 * because a fresh import isn't queryable/triaged yet; the DefectDojo engagement
 * is still linked for drill-down. This makes CLI == report.json == imported set.
 */
export interface ReportResult {
    htmlPath: string;
    jsonPath: string;
    /** Severity tally of exactly what was written to report.json (fed to the CLI). */
    severityCounts: Record<Severity, number>;
    findingCount: number;
}
export declare function runReport(ctx: RunContext, engagementId: number | null): Promise<ReportResult>;
