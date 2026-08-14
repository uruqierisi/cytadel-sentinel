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
}
export declare function renderHtml(d: ReportData): string;
