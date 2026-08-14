import { writeFile } from "node:fs/promises";
import type { Severity } from "../normalize/types.js";

/**
 * DefectDojo "Generic Findings Import" JSON. Used by tools that have no native
 * DefectDojo parser (dalfox, sqlmap): we emit this one file that BOTH the
 * DefectDojo import-scan endpoint and our own Normalize parser consume.
 */

export interface GenericFinding {
  sourceTool: string;
  title: string;
  description: string;
  severity: Severity;
  /** CWE id (e.g. 79 for XSS, 89 for SQLi). */
  cwe: number | null;
  /** The concrete URL/param the finding applies to. */
  endpoint: string;
  /** Stable id so DefectDojo can dedupe across runs. */
  uniqueId: string;
  evidence: string | null;
}

const SEVERITY_LABEL: Record<Severity, string> = {
  INFO: "Info",
  LOW: "Low",
  MEDIUM: "Medium",
  HIGH: "High",
  CRITICAL: "Critical",
};

/** Today's date as YYYY-MM-DD (DefectDojo requires a date per finding). */
function today(): string {
  return new Date().toISOString().slice(0, 10);
}

/**
 * Write a DefectDojo Generic Findings Import file. The same JSON is later read
 * by normalize/parseGeneric, so the shape here is the contract for both.
 */
export async function writeGenericFindingsFile(
  outPath: string,
  findings: GenericFinding[],
): Promise<void> {
  const doc = {
    findings: findings.map((f) => ({
      title: f.title,
      description: f.description,
      severity: SEVERITY_LABEL[f.severity],
      date: today(),
      cwe: f.cwe ?? undefined,
      file_path: f.endpoint,
      unique_id_from_tool: f.uniqueId,
      dynamic_finding: true,
      static_finding: false,
      endpoints: [f.endpoint],
      // Retained for our own Normalize parser (ignored by DefectDojo).
      sentinel_tool: f.sourceTool,
      sentinel_evidence: f.evidence ?? "",
    })),
  };
  await writeFile(outPath, JSON.stringify(doc, null, 2), "utf8");
}
