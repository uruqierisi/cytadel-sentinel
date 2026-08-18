import { writeFile } from "node:fs/promises";
import path from "node:path";
import { prisma } from "../../db/client.js";
import { audit } from "../../lib/audit.js";
import { runDir, ensureRunDirs } from "../../lib/paths.js";
import { authSecretValues, scrubString } from "../../lib/scrub.js";
import { coverageLimitations } from "../../core/coverage.js";
import { type Severity } from "../normalize/types.js";
import { renderHtml, type ReportData, type ReportFinding } from "./template.js";
import { remediationFor } from "./remediation.js";
import { cvssFor, businessImpactFor } from "./cvss.js";
import { diffFindings } from "./retest.js";
import { buildExecutive } from "./executive.js";
import type { RunContext } from "../../core/context.js";

/**
 * Report stage. Renders a Cytadel-branded HTML + JSON report under
 * reports/<run-id>/ from the LOCAL normalized finding table — the exact same
 * set the CLI counts and that was imported to DefectDojo. Reading back from
 * DefectDojo here previously caused a divergence (CLI showed N, report.json 0)
 * because a fresh import isn't queryable/triaged yet; the DefectDojo engagement
 * is still linked for drill-down. This makes CLI == report.json == imported set.
 */
export interface ReportResult {
  htmlPath: string;
  jsonPath: string;
  /** Severity tally of exactly what was written to report.json (fed to the CLI). */
  severityCounts: Record<Severity, number>;
  findingCount: number;
}

const EMPTY_COUNTS: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

/** Per-finding dedupe key used to diff across runs (retest). */
interface LocalFinding extends ReportFinding {
  key: string;
}

/** Best-effort CWE derivation from the raw tool record or the source tool. */
function cweFromRaw(raw: unknown, sourceTool: string): number | null {
  const r = (raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {}) as Record<string, unknown>;
  const direct = cweNum(r["cwe"]);
  if (direct) return direct;
  const info = (r["info"] && typeof r["info"] === "object" ? (r["info"] as Record<string, unknown>) : {}) as Record<string, unknown>;
  const cls = (info["classification"] && typeof info["classification"] === "object" ? (info["classification"] as Record<string, unknown>) : {}) as Record<string, unknown>;
  const nucleiCwe = Array.isArray(cls["cwe-id"]) ? cweNum((cls["cwe-id"] as unknown[])[0]) : cweNum(cls["cwe-id"]);
  if (nucleiCwe) return nucleiCwe;
  // Source-tool defaults for the injection tools.
  if (sourceTool === "sqlmap") return 89;
  if (sourceTool === "dalfox") return 79;
  return null;
}

function cweNum(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string") {
    const n = Number(v.replace(/\D+/g, ""));
    return Number.isFinite(n) && n > 0 ? n : null;
  }
  return null;
}

async function collectFromLocal(runId: string): Promise<LocalFinding[]> {
  const rows = await prisma.finding.findMany({ where: { runId }, orderBy: { severity: "desc" } });
  return rows.map((r) => {
    const severity = r.severity as Severity;
    const cwe = cweFromRaw(r.raw, r.sourceTool);
    const cvss = cvssFor({ cwe, severity });
    return {
      key: r.dedupeKey,
      title: r.name,
      severity,
      target: r.target,
      sourceTool: r.sourceTool,
      cve: null,
      cvss: r.cvss ?? null,
      description: null,
      evidence: r.evidence ?? null,
      verified: r.verificationStatus === "VERIFIED",
      active: true,
      // WP5 enrichment.
      cwe,
      cvssVector: cvss.vector,
      cvssScore: cvss.score,
      businessImpact: businessImpactFor({ cwe, severity }),
      remediation: remediationFor({ cwe, sourceTool: r.sourceTool }),
    };
  });
}

/** Prior-run findings (key + severity) for the retest diff. */
async function priorFindings(runId: string): Promise<Array<{ key: string; severity: Severity; title: string; target: string }>> {
  const rows = await prisma.finding.findMany({ where: { runId } });
  return rows.map((r) => ({ key: r.dedupeKey, severity: r.severity as Severity, title: r.name, target: r.target }));
}

export async function runReport(ctx: RunContext, engagementId: number | null): Promise<ReportResult> {
  ctx.log.info({ engagementId }, "report: starting");
  await audit({ runId: ctx.runId, actor: ctx.actor, action: "STAGE_START", detail: { stage: "report" } });
  await ensureRunDirs(ctx.runId);

  const run = await prisma.run.findUniqueOrThrow({ where: { id: ctx.runId } });
  const assetCount = await prisma.asset.count({ where: { runId: ctx.runId } });

  // Source of truth = the local normalized findings persisted this run. This is
  // exactly what the CLI counts and what was imported to DefectDojo, so all three
  // agree. The DefectDojo engagement is still linked (below) for triage.
  const findings = await collectFromLocal(ctx.runId);

  // Sort CRITICAL -> INFO and tally.
  const rank: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  findings.sort((a, b) => rank[a.severity] - rank[b.severity]);
  const severityCounts = { ...EMPTY_COUNTS };
  for (const f of findings) severityCounts[f.severity]++;

  // WP5 retest: diff against a prior run when the scope references one.
  let retest: ReportData["retest"] = null;
  const priorRunId = ctx.scope.retest_of;
  if (priorRunId) {
    try {
      const prev = await priorFindings(priorRunId);
      const diff = diffFindings(
        findings.map((f) => ({ key: f.key, severity: f.severity })),
        prev.map((p) => ({ key: p.key, severity: p.severity })),
      );
      for (const f of findings) f.retestStatus = diff.statusByKey.get(f.key);
      const fixedByKey = new Map(prev.map((p) => [p.key, p]));
      retest = {
        priorRunId,
        counts: diff.counts,
        fixed: diff.fixed.map((d) => {
          const p = fixedByKey.get(d.key)!;
          return { title: p.title, severity: p.severity, target: p.target };
        }),
      };
      ctx.log.info({ priorRunId, counts: diff.counts }, "report: retest diff computed");
    } catch (err) {
      ctx.log.warn({ err, priorRunId }, "report: retest diff failed — prior run unavailable");
    }
  }

  const executive = buildExecutive(findings, severityCounts, {
    hosts: ctx.coverage.hosts,
    endpoints: ctx.coverage.endpoints,
    params: ctx.coverage.params,
    authState: ctx.coverage.auth.state,
    authMode: ctx.coverage.auth.mode,
    candidatesBySource: ctx.coverage.candidatesBySource,
    injection: ctx.coverage.injection,
    tools: ctx.coverage.tools,
    limitations: coverageLimitations(ctx.coverage),
  });

  const data: ReportData = {
    runId: ctx.runId,
    generatedAt: new Date().toISOString(),
    scope: {
      name: ctx.scope.name,
      authorizedBy: ctx.scope.authorized_by,
      authorizationRef: ctx.scope.authorization_ref,
      scopeHash: ctx.scopeHash,
      allowDestructive: ctx.allowDestructive,
      client: ctx.scope.client ?? null,
    },
    actor: ctx.actor,
    startedAt: run.startedAt.toISOString(),
    finishedAt: (run.finishedAt ?? new Date()).toISOString(),
    assetCount,
    activeInjection: ctx.allowDestructive,
    engagementId,
    defectDojoUrl: process.env.DEFECTDOJO_URL?.replace(/\/+$/, "") ?? null,
    severityCounts,
    findings,
    coverage: {
      hosts: ctx.coverage.hosts,
      endpoints: ctx.coverage.endpoints,
      params: ctx.coverage.params,
      authState: ctx.coverage.auth.state,
      authMode: ctx.coverage.auth.mode,
      candidatesBySource: ctx.coverage.candidatesBySource,
      injection: { get: ctx.coverage.injection.get, post: ctx.coverage.injection.post, ran: ctx.coverage.injection.ran },
      tools: ctx.coverage.tools,
      limitations: coverageLimitations(ctx.coverage),
    },
    executive,
    retest,
  };

  const dir = runDir(ctx.runId);
  const htmlPath = path.join(dir, "report.html");
  const jsonPath = path.join(dir, "report.json");
  // Defense-in-depth: the report is built from local findings (which shouldn't
  // contain auth material), but scrub the rendered output anyway so a session
  // token can never reach the client-facing report.
  const secrets = authSecretValues(ctx.auth);
  await writeFile(htmlPath, scrubString(renderHtml(data), secrets), "utf8");
  await writeFile(jsonPath, scrubString(JSON.stringify(data, null, 2), secrets), "utf8");

  await prisma.run.update({ where: { id: ctx.runId }, data: { reportPath: htmlPath } });
  ctx.log.info({ htmlPath, jsonPath, findings: findings.length }, "report: complete");
  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "REPORT",
    detail: { htmlPath, jsonPath, findings: findings.length },
  });
  return { htmlPath, jsonPath, severityCounts, findingCount: findings.length };
}
