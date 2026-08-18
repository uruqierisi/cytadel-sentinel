/**
 * Append-only audit trail.
 *
 * NON-NEGOTIABLE RULE: every run records who triggered it, timestamp, scope
 * hash, tools+versions used, and every target touched — and every scope
 * decision. This module is the single choke point for that.
 *
 * Durability: each event is written BOTH to Postgres (AuditLog) and to an
 * append-only JSONL sidecar under audit/. The two are cross-checkable; the
 * JSONL survives even if the DB is unavailable. Nothing here ever updates or
 * deletes a prior record.
 */
export type AuditAction = "RUN_START" | "RUN_COMPLETE" | "RUN_FAILED" | "SCOPE_LOAD" | "SCOPE_ACCEPT" | "SCOPE_REJECT" | "STAGE_START" | "STAGE_COMPLETE" | "TOOL_EXEC" | "TARGET_TOUCHED" | "IMPORT" | "REPORT" | "DESTRUCTIVE_GATE" | "AUTH_ESTABLISHED" | "AUTH_SESSION_LOST" | "AUTH_REESTABLISHED" | "AUTH_DEGRADED";
export interface AuditEvent {
    runId?: string;
    actor?: string;
    action: AuditAction;
    scopeHash?: string;
    target?: string;
    tools?: Record<string, string>;
    detail?: Record<string, unknown>;
}
/** Resolve the acting identity (env override, else OS user). */
export declare function currentActor(): string;
/** Stable sha256 of any JSON-serializable value (used for scope hashing). */
export declare function sha256Of(value: unknown): string;
/**
 * Record one audit event. Writes JSONL first (cheap, always available), then
 * the DB. A DB failure is logged but never throws — losing the pipeline over an
 * audit write would be worse than a degraded-but-flagged trail. The JSONL line
 * is the tamper-evident source of record.
 */
export declare function audit(event: AuditEvent): Promise<void>;
