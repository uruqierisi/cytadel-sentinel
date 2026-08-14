/**
 * The unified finding schema. Every tool's raw output is normalized into this
 * shape before it is persisted or handed to DefectDojo. Keeping one schema is
 * what lets dedupe, verification, and reporting be tool-agnostic.
 */
export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export interface UnifiedFinding {
    /** Tool that produced this: nuclei | nikto | testssl | retirejs. */
    sourceTool: string;
    /** Rule/template id where the tool provides one (nuclei template-id, etc.). */
    templateId: string | null;
    name: string;
    /** Host or URL the finding applies to. Always in-scope by construction. */
    target: string;
    /** Matched-at URL / port / path, when the tool reports one. */
    matchedLocation: string | null;
    severity: Severity;
    cvss: number | null;
    epss: number | null;
    /** Short human-readable evidence snippet. */
    evidence: string | null;
    /** Full raw tool record, retained for audit + report drill-down. */
    raw: unknown;
}
/**
 * Dedupe key: sourceTool + templateId + host + matchedLocation.
 * Two findings with the same key are the same issue within a run; DefectDojo
 * additionally dedupes across runs.
 */
export declare function dedupeKey(f: UnifiedFinding): string;
/** Reduce a target/URL to a bare host for stable dedupe. */
export declare function hostOf(target: string): string;
/** Map an arbitrary tool severity string onto our enum. */
export declare function normalizeSeverity(input: string | null | undefined): Severity;
