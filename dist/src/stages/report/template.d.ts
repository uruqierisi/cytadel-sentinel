import type { Severity } from "../normalize/types.js";
/**
 * Cytadel-branded standalone HTML report. Fully self-contained (inline CSS, SVG
 * logo) so it can be emailed/archived. Every dynamic value is HTML-escaped.
 */
export interface ReportFinding {
    title: string;
    severity: Severity;
    target: string;
    sourceTool: string;
    cve: string | null;
    cvss: number | null;
    description: string | null;
    evidence: string | null;
    verified: boolean;
    active: boolean;
}
export interface CoverageReport {
    hosts: {
        discovered: number;
        tested: number;
    };
    endpoints: {
        discovered: number;
        tested: number;
    };
    params: {
        discovered: number;
        tested: number;
    };
    /** authenticated | anonymous | degraded */
    authState: string;
    authMode: string;
    candidatesBySource: Record<string, number>;
    injection: {
        get: number;
        post: number;
        ran: boolean;
    };
    tools: Array<{
        name: string;
        version: string;
    }>;
    /** Human-readable coverage limitations (caps hit, skips, empty sources). */
    limitations: string[];
}
export interface ReportData {
    runId: string;
    generatedAt: string;
    scope: {
        name: string;
        authorizedBy: string;
        authorizationRef: string;
        scopeHash: string;
        allowDestructive: boolean;
    };
    actor: string;
    startedAt: string;
    finishedAt: string;
    assetCount: number;
    /** Whether active injection (dalfox/sqlmap) ran (destructive gate open). */
    activeInjection: boolean;
    engagementId: number | null;
    defectDojoUrl: string | null;
    severityCounts: Record<Severity, number>;
    findings: ReportFinding[];
    /** WP4 — what was tested vs discovered, and coverage limitations. */
    coverage: CoverageReport;
}
export declare function renderHtml(d: ReportData): string;
