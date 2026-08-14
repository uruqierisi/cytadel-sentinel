import type { RunContext } from "../../core/context.js";
/**
 * Report stage. Pulls the engagement's findings from DefectDojo (post-dedupe /
 * triage) and renders a Cytadel-branded HTML + JSON report under
 * reports/<run-id>/. Falls back to the local finding table if DefectDojo can't
 * be reached, so a report always lands.
 */
export interface ReportResult {
    htmlPath: string;
    jsonPath: string;
}
export declare function runReport(ctx: RunContext, engagementId: number | null): Promise<ReportResult>;
