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
export function dedupeKey(f: UnifiedFinding): string {
  const parts = [
    f.sourceTool,
    f.templateId ?? f.name,
    hostOf(f.target),
    f.matchedLocation ?? "",
  ];
  return parts.join("|").toLowerCase();
}

/** Reduce a target/URL to a bare host for stable dedupe. */
export function hostOf(target: string): string {
  try {
    if (target.includes("://")) return new URL(target).host.toLowerCase();
  } catch {
    /* fall through */
  }
  return target.split("/")[0]?.split(":")[0]?.toLowerCase() ?? target.toLowerCase();
}

/** Map an arbitrary tool severity string onto our enum. */
export function normalizeSeverity(input: string | null | undefined): Severity {
  const s = (input ?? "").toLowerCase();
  if (s.startsWith("crit")) return "CRITICAL";
  if (s.startsWith("high")) return "HIGH";
  if (s.startsWith("med") || s === "moderate") return "MEDIUM";
  if (s.startsWith("low")) return "LOW";
  return "INFO";
}
