import type { Severity } from "../normalize/types.js";
import type { ExecutiveSummary, ReportFinding } from "./template.js";
import type { CoverageReport } from "./template.js";

/**
 * Executive summary (WP5): a plain-language overview for non-technical readers —
 * risk posture, the 2-3 highest-impact issues in business terms, and a one-line
 * coverage statement. Pure/testable.
 */

const RANK: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

function posture(counts: Record<Severity, number>): string {
  const c = counts.CRITICAL, h = counts.HIGH, m = counts.MEDIUM;
  if (c > 0) return `Critical risk — ${c} critical and ${h} high-severity issue(s) require immediate remediation.`;
  if (h > 0) return `High risk — ${h} high-severity issue(s) need prompt attention.`;
  if (m > 0) return `Moderate risk — ${m} medium-severity issue(s) should be scheduled for remediation.`;
  const low = counts.LOW + counts.INFO;
  if (low > 0) return `Low risk — only ${low} low/informational issue(s) were identified.`;
  return "No exploitable vulnerabilities were confirmed within the tested surface.";
}

function coverageLine(cov: CoverageReport): string {
  const auth =
    cov.authState === "authenticated"
      ? "authenticated"
      : cov.authState === "degraded"
        ? "partially authenticated (session degraded)"
        : "unauthenticated";
  const lim = cov.limitations.length
    ? ` ${cov.limitations.length} coverage limitation(s) are listed below.`
    : " No coverage limitations were recorded.";
  return (
    `Testing was ${auth}. ${cov.hosts.tested}/${cov.hosts.discovered} host(s), ` +
    `${cov.endpoints.tested}/${cov.endpoints.discovered} endpoint(s) and ` +
    `${cov.params.tested}/${cov.params.discovered} injectable parameter(s) were exercised.` +
    lim
  );
}

/** Build the executive summary from findings + coverage. */
export function buildExecutive(
  findings: ReportFinding[],
  counts: Record<Severity, number>,
  cov: CoverageReport,
): ExecutiveSummary {
  const top = [...findings]
    .sort((a, b) => RANK[a.severity] - RANK[b.severity])
    .slice(0, 3)
    .map((f) => {
      const impact = f.businessImpact ?? `${f.severity} severity issue in ${f.target}.`;
      return `${f.severity} — ${f.title}: ${impact}`;
    });
  return { posture: posture(counts), topIssues: top, coverageLine: coverageLine(cov) };
}
