import type { Severity } from "../normalize/types.js";

/**
 * Retest diff (WP5).
 *
 * When a run references a prior engagement (a previous run id), we diff the two
 * finding sets by their stable dedupe key to produce a "Status vs previous"
 * verdict per finding — the standard paid retest deliverable. Pure/testable.
 */

export type RetestStatus = "new" | "present" | "fixed" | "regressed";

export interface DiffFinding {
  key: string;
  severity: Severity;
}

const RANK: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

export interface RetestDiff {
  /** Status for each CURRENT finding, keyed by dedupe key. */
  statusByKey: Map<string, RetestStatus>;
  /** Findings present in the PRIOR run but gone now (fixed). */
  fixed: DiffFinding[];
  counts: Record<RetestStatus, number>;
}

/**
 * Diff current vs previous findings.
 *  - key in both, same/lower severity  -> "present"
 *  - key in both, MORE severe now       -> "regressed"
 *  - key only in current                -> "new"
 *  - key only in previous               -> "fixed"
 */
export function diffFindings(current: DiffFinding[], previous: DiffFinding[]): RetestDiff {
  const prevByKey = new Map(previous.map((f) => [f.key, f]));
  const currKeys = new Set(current.map((f) => f.key));
  const statusByKey = new Map<string, RetestStatus>();
  const counts: Record<RetestStatus, number> = { new: 0, present: 0, fixed: 0, regressed: 0 };

  for (const f of current) {
    const prev = prevByKey.get(f.key);
    let status: RetestStatus;
    if (!prev) status = "new";
    else if (RANK[f.severity] < RANK[prev.severity]) status = "regressed"; // higher severity now
    else status = "present";
    statusByKey.set(f.key, status);
    counts[status]++;
  }

  const fixed = previous.filter((f) => !currKeys.has(f.key));
  counts.fixed = fixed.length;

  return { statusByKey, fixed, counts };
}
