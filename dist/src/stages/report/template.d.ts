import type { Severity } from "../normalize/types.js";
/**
 * Cytadel-branded standalone HTML report. Fully self-contained (inline CSS, SVG
 * logo) so it can be emailed/archived. Every dynamic value is HTML-escaped.
 */
export type RetestStatusLabel = "new" | "present" | "fixed" | "regressed";
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
    /** WP5: CWE id, CVSS v3.1 default vector/score, business impact, remediation. */
    cwe?: number | null;
    cvssVector?: string;
    cvssScore?: number;
    businessImpact?: string;
    remediation?: {
        summary: string;
        guidance: string;
    };
    /** WP5 retest: status vs the prior engagement (undefined when not a retest). */
    retestStatus?: RetestStatusLabel;
}
export interface RetestReport {
    priorRunId: string;
    counts: {
        new: number;
        present: number;
        fixed: number;
        regressed: number;
    };
    /** Findings fixed since the prior run (present then, gone now). */
    fixed: Array<{
        title: string;
        severity: Severity;
        target: string;
    }>;
}
export interface ExecutiveSummary {
    /** One-line risk posture, e.g. "High risk — 2 high-severity issues need prompt attention". */
    posture: string;
    /** 2-3 highest-impact issues, in business terms. */
    topIssues: string[];
    /** Plain-language coverage sentence. */
    coverageLine: string;
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
        /** WP5 report metadata. */
        client?: string | null;
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
    /** WP5 — plain-language executive summary. */
    executive: ExecutiveSummary;
    /** WP5 — retest diff vs a prior engagement, when configured. */
    retest?: RetestReport | null;
}
export declare function renderHtml(d: ReportData): string;
