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
 *
 * IMPORTANT: DefectDojo's Generic Findings Import serializer has a strict field
 * allowlist and rejects the whole import (HTTP 400 "Not allowed fields") if any
 * unknown key is present. So we emit ONLY standard fields — no custom
 * `sentinel_*` keys. The evidence (payload / technique / DBMS) is folded into the
 * standard `description` so it survives to BOTH DefectDojo and our local parser;
 * parseGeneric recovers evidence from `description` and the source tool from the
 * artifact's tool name.
 */
export interface GenericImportDoc {
  findings: Array<Record<string, unknown>>;
}

/**
 * Build the DefectDojo Generic Findings Import document — ONLY standard,
 * allowlisted fields. Pure and testable (no fs). Kept separate so we can assert
 * the payload carries no custom keys that would 400 the import.
 */
export function buildGenericFindingsDoc(findings: GenericFinding[]): GenericImportDoc {
  return {
    findings: findings.map((f) => ({
      title: f.title,
      description: buildDescription(f),
      severity: SEVERITY_LABEL[f.severity],
      date: today(),
      cwe: f.cwe ?? undefined,
      file_path: f.endpoint,
      unique_id_from_tool: f.uniqueId,
      dynamic_finding: true,
      static_finding: false,
      endpoints: [f.endpoint],
    })),
  };
}

export async function writeGenericFindingsFile(
  outPath: string,
  findings: GenericFinding[],
): Promise<void> {
  await writeFile(outPath, JSON.stringify(buildGenericFindingsDoc(findings), null, 2), "utf8");
}

/** Fold evidence into the description so it reaches DefectDojo AND report.json. */
function buildDescription(f: GenericFinding): string {
  return [f.description, f.evidence ? `Evidence — ${f.evidence}` : ""].filter(Boolean).join("\n\n");
}
