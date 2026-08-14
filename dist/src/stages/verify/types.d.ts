import type { UnifiedFinding } from "../normalize/types.js";
/**
 * Verification layer contract (Phase 2 — interfaces designed now, most replays
 * stubbed). Classifies each finding into how it MAY be confirmed:
 *
 *   AUTO        deterministic + non-destructive (missing header, exposed
 *               endpoint, reflected value, broken access control). Safe to
 *               replay a targeted request and match.
 *   MANUAL      needs a browser or human reasoning (DOM XSS, chained logic).
 *               Routed to a review queue; never auto-touched.
 *   NEVER_AUTO  destructive-class (SQLi, RCE, ...). Never verified automatically.
 *
 * NON-NEGOTIABLE: replays use lib/http.ts (structured method/url/headers/body).
 * Finding data is NEVER interpolated into a shell string.
 */
export type VerificationClass = "AUTO" | "MANUAL" | "NEVER_AUTO";
export type VerificationOutcome = "VERIFIED" | "LOW_CONFIDENCE" | "MANUAL_REVIEW" | "NEVER_AUTO";
export interface ReplayEvidence {
    requestLine: string;
    requestHeaders: Record<string, string>;
    responseStatus: number;
    responseHeadersSnippet: Record<string, string | string[] | undefined>;
    responseBodySnippet: string;
}
export interface VerificationResult {
    finding: UnifiedFinding;
    classification: VerificationClass;
    outcome: VerificationOutcome;
    /** Reproducible request/response evidence when a replay ran. */
    evidence?: ReplayEvidence;
    note?: string;
}
/**
 * A Verifier knows how to confirm one kind of AUTO finding. `applies` decides
 * ownership; `verify` performs the (non-destructive) replay and matches.
 */
export interface Verifier {
    id: string;
    applies(finding: UnifiedFinding): boolean;
    verify(finding: UnifiedFinding, authHeaders: Record<string, string>): Promise<VerificationResult>;
}
