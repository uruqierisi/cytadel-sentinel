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
  remediation?: { summary: string; guidance: string };
  /** WP5 retest: status vs the prior engagement (undefined when not a retest). */
  retestStatus?: RetestStatusLabel;
}

export interface RetestReport {
  priorRunId: string;
  counts: { new: number; present: number; fixed: number; regressed: number };
  /** Findings fixed since the prior run (present then, gone now). */
  fixed: Array<{ title: string; severity: Severity; target: string }>;
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
  hosts: { discovered: number; tested: number };
  endpoints: { discovered: number; tested: number };
  params: { discovered: number; tested: number };
  /** authenticated | anonymous | degraded */
  authState: string;
  authMode: string;
  candidatesBySource: Record<string, number>;
  injection: { get: number; post: number; ran: boolean };
  tools: Array<{ name: string; version: string }>;
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

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "#e0245e",
  HIGH: "#f66d3b",
  MEDIUM: "#f5b301",
  LOW: "#2fa7ff",
  INFO: "#7a8699",
};

function esc(v: unknown): string {
  return String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function severityBadge(sev: Severity): string {
  return `<span class="sev" style="background:${SEVERITY_COLOR[sev]}">${sev}</span>`;
}

function summaryCards(counts: Record<Severity, number>): string {
  return SEVERITY_ORDER.map(
    (sev) => `
      <div class="card" style="--accent:${SEVERITY_COLOR[sev]}">
        <div class="card-num">${counts[sev] ?? 0}</div>
        <div class="card-label">${sev}</div>
      </div>`,
  ).join("");
}

const RETEST_LABEL: Record<RetestStatusLabel, string> = {
  new: "NEW",
  present: "STILL PRESENT",
  fixed: "FIXED",
  regressed: "REGRESSED",
};

function retestBadge(status: RetestStatusLabel | undefined): string {
  if (!status) return "";
  return `<span class="retest retest-${status}">${RETEST_LABEL[status]}</span>`;
}

function findingRow(f: ReportFinding): string {
  const flags = [
    f.verified ? '<span class="tag verified">verified</span>' : "",
    f.active ? "" : '<span class="tag inactive">inactive</span>',
    retestBadge(f.retestStatus),
  ]
    .filter(Boolean)
    .join(" ");
  const cvss =
    f.cvssScore != null
      ? `CVSS ${esc(f.cvssScore)}${f.cvssVector ? ` <span class="mono dim">${esc(f.cvssVector)}</span>` : ""}`
      : f.cvss != null
        ? "CVSS " + esc(f.cvss)
        : "";
  return `
    <tr>
      <td>${severityBadge(f.severity)}</td>
      <td>
        <div class="f-title">${esc(f.title)} ${flags}</div>
        <div class="f-meta">${esc(f.sourceTool)}${f.cve ? " · " + esc(f.cve) : ""}${f.cwe ? " · CWE-" + esc(f.cwe) : ""}${
          cvss ? " · " + cvss : ""
        }</div>
        ${f.businessImpact ? `<div class="f-impact"><span class="lbl">Business impact:</span> ${esc(f.businessImpact)}</div>` : ""}
        ${f.description ? `<div class="f-desc">${esc(f.description).slice(0, 600)}</div>` : ""}
        ${f.evidence ? `<pre class="f-evidence">${esc(f.evidence).slice(0, 1200)}</pre>` : ""}
        ${
          f.remediation
            ? `<div class="f-remediation"><span class="lbl">Remediation:</span> ${esc(f.remediation.summary)}
                 <div class="f-remediation-body">${esc(f.remediation.guidance)}</div></div>`
            : ""
        }
      </td>
      <td class="f-target">${esc(f.target)}</td>
    </tr>`;
}

function executiveSection(e: ExecutiveSummary): string {
  const issues = e.topIssues.length
    ? e.topIssues.map((i) => `<li>${esc(i)}</li>`).join("")
    : "<li>No exploitable issues were confirmed in the tested surface.</li>";
  return `
  <section class="exec">
    <h2>Executive summary</h2>
    <p class="exec-posture">${esc(e.posture)}</p>
    <div class="exec-issues"><div class="k">Highest-impact issues</div><ul>${issues}</ul></div>
    <p class="exec-coverage">${esc(e.coverageLine)}</p>
  </section>`;
}

function retestSection(r: RetestReport): string {
  const fixed = r.fixed.length
    ? `<ul class="cov-lims">${r.fixed.map((f) => `<li class="ok">FIXED — ${esc(f.title)} <span class="dim">(${esc(f.target)})</span></li>`).join("")}</ul>`
    : "";
  return `
  <h2>Retest — status vs previous engagement</h2>
  <div class="meta">
    <div><div class="k">Prior run</div><div class="v mono">${esc(r.priorRunId)}</div></div>
    <div><div class="k">New</div><div class="v cov-bad">${r.counts.new}</div></div>
    <div><div class="k">Regressed</div><div class="v cov-bad">${r.counts.regressed}</div></div>
    <div><div class="k">Still present</div><div class="v cov-warn">${r.counts.present}</div></div>
    <div><div class="k">Fixed</div><div class="v cov-ok">${r.counts.fixed}</div></div>
  </div>
  ${fixed}`;
}

function coverageSection(c: CoverageReport): string {
  const pair = (label: string, tested: number, discovered: number): string => `
      <div><div class="k">${label} tested / discovered</div><div class="v">${tested} / ${discovered}</div></div>`;
  const authClass = c.authState === "authenticated" ? "ok" : c.authState === "degraded" ? "bad" : "warn";
  const sources = Object.entries(c.candidatesBySource)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${esc(s)} ${n}`)
    .join(" · ") || "none";
  const toolList = c.tools.length
    ? c.tools.map((t) => `${esc(t.name)} <span class="dim">${esc(t.version)}</span>`).join(", ")
    : "(none resolved)";
  const lims = c.limitations.length
    ? c.limitations.map((l) => `<li>${esc(l)}</li>`).join("")
    : `<li class="ok">No coverage limitations recorded for this run.</li>`;

  return `
  <h2>Coverage</h2>
  <div class="meta">
    ${pair("Hosts", c.hosts.tested, c.hosts.discovered)}
    ${pair("Endpoints", c.endpoints.tested, c.endpoints.discovered)}
    ${pair("Injectable params", c.params.tested, c.params.discovered)}
    <div><div class="k">Authentication</div><div class="v cov-${authClass}">${esc(c.authState)}${
      c.authMode && c.authMode !== "none" ? ` <span class="dim">(${esc(c.authMode)})</span>` : ""
    }</div></div>
    <div><div class="k">Injection candidates by source</div><div class="v">${sources}</div></div>
    <div><div class="k">Body (POST/PUT) tested</div><div class="v">${c.injection.post > 0 ? `yes (${c.injection.post})` : "no"}</div></div>
    <div style="grid-column:1/-1"><div class="k">Tools used</div><div class="v">${toolList}</div></div>
  </div>
  <h2 style="font-size:13px;margin-top:16px">Coverage limitations</h2>
  <ul class="cov-lims">${lims}</ul>`;
}

const LOGO = `
<svg width="42" height="42" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M32 3l24 9v16c0 15-10 27-24 33C18 55 8 43 8 28V12l24-9z" fill="#0b1f3a" stroke="#28e0c8" stroke-width="2.5"/>
  <path d="M32 16l14 5v9c0 9-6 16-14 20-8-4-14-11-14-20v-9l14-5z" fill="#122c4f"/>
  <path d="M24 33l6 6 12-14" stroke="#28e0c8" stroke-width="3.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

export function renderHtml(d: ReportData): string {
  const rows = d.findings.length
    ? d.findings.map(findingRow).join("")
    : `<tr><td colspan="3" class="empty">No findings reported for this engagement.</td></tr>`;

  const dojoLink =
    d.defectDojoUrl && d.engagementId
      ? `<a href="${esc(d.defectDojoUrl)}/engagement/${d.engagementId}" target="_blank" rel="noopener">Open in DefectDojo →</a>`
      : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Cytadel Sentinel — Report ${esc(d.runId)}</title>
<style>
  :root{
    --bg:#0a1626; --panel:#0f2036; --panel-2:#132a45; --ink:#e8f0fb; --muted:#8ea3c0;
    --line:#1e3a5c; --brand:#28e0c8;
  }
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink)}
  .wrap{max-width:1080px;margin:0 auto;padding:32px 20px 64px}
  header{display:flex;align-items:center;gap:14px;padding-bottom:20px;border-bottom:1px solid var(--line)}
  header h1{font-size:20px;margin:0;letter-spacing:.3px}
  header .sub{color:var(--muted);font-size:13px}
  .brand-mark{color:var(--brand);font-weight:700}
  .meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:24px 0}
  .meta div{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
  .meta .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.6px}
  .meta .v{font-size:14px;margin-top:3px;word-break:break-word}
  .cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:8px 0 28px}
  .card{background:var(--panel);border:1px solid var(--line);border-top:3px solid var(--accent);border-radius:10px;padding:16px;text-align:center}
  .card-num{font-size:30px;font-weight:700}
  .card-label{color:var(--muted);font-size:12px;letter-spacing:.6px;margin-top:2px}
  h2{font-size:15px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin:28px 0 12px}
  table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
  th,td{text-align:left;padding:12px 14px;border-bottom:1px solid var(--line);vertical-align:top}
  th{background:var(--panel-2);color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.6px}
  tr:last-child td{border-bottom:none}
  .sev{display:inline-block;color:#08131f;font-weight:700;font-size:11px;padding:3px 8px;border-radius:6px;letter-spacing:.4px}
  .f-title{font-weight:600}
  .f-meta{color:var(--muted);font-size:12px;margin-top:2px}
  .f-desc{margin-top:8px;color:#cdd9ec;font-size:13px}
  .f-evidence{margin-top:8px;background:#08131f;border:1px solid var(--line);border-radius:8px;padding:10px;white-space:pre-wrap;font-size:12px;color:#a8c6e6;overflow-x:auto}
  .f-target{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#bcd2ee;white-space:nowrap}
  .tag{font-size:10px;padding:1px 6px;border-radius:5px;border:1px solid var(--line);color:var(--muted)}
  .tag.verified{color:var(--brand);border-color:var(--brand)}
  .empty{color:var(--muted);text-align:center;padding:24px}
  .dim{color:var(--muted);font-size:12px}
  .cov-ok{color:#2f9e6b;font-weight:600}
  .cov-warn{color:#f5b301;font-weight:600}
  .cov-bad{color:#e0245e;font-weight:700}
  .cov-lims{margin:6px 0 0;padding-left:18px;color:#cdd9ec;font-size:13px}
  .cov-lims li{margin:4px 0}
  .cov-lims li.ok{color:#2f9e6b;list-style:none;margin-left:-18px}
  .mono{font-family:ui-monospace,Menlo,Consolas,monospace}
  .exec{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--brand);border-radius:10px;padding:18px 20px;margin:22px 0}
  .exec h2{margin:0 0 8px}
  .exec-posture{font-size:16px;font-weight:600;color:var(--ink);margin:0 0 10px}
  .exec-issues .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.6px}
  .exec-issues ul{margin:6px 0 0;padding-left:18px}
  .exec-issues li{margin:4px 0;color:#cdd9ec;font-size:14px}
  .exec-coverage{color:var(--muted);font-size:13px;margin:12px 0 0}
  .f-impact{margin-top:8px;font-size:13px;color:#e8d9b0}
  .f-remediation{margin-top:10px;font-size:13px;color:#cdeecd}
  .f-remediation-body{margin-top:4px;color:#bcd2ee;font-size:12.5px}
  .lbl{color:var(--brand);font-weight:600}
  .retest{font-size:10px;padding:1px 6px;border-radius:5px;font-weight:700;letter-spacing:.4px}
  .retest-new{background:#e0245e;color:#fff}
  .retest-regressed{background:#e0245e;color:#fff}
  .retest-present{background:#f5b301;color:#08131f}
  .retest-fixed{background:#2f9e6b;color:#fff}
  .banner{margin:20px 0;padding:10px 14px;border-radius:8px;background:#1a1230;border:1px solid #6b3fa0;color:#d9c6ff;font-size:13px}
  footer{margin-top:36px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:16px}
  a{color:var(--brand)}
</style>
</head>
<body>
<div class="wrap">
  <header>
    ${LOGO}
    <div>
      <h1><span class="brand-mark">CYTADEL</span> SENTINEL — Security Report</h1>
      <div class="sub">Authorized web-application penetration test${
        d.scope.client ? ` · Client: ${esc(d.scope.client)}` : ""
      } · Engagement: ${esc(d.scope.name)}</div>
      <div class="sub">Tester: ${esc(d.actor)} · ${esc(d.startedAt.slice(0, 10))} → ${esc(d.finishedAt.slice(0, 10))} · Run ${esc(d.runId)}</div>
    </div>
  </header>

  ${executiveSection(d.executive)}

  ${
    d.scope.allowDestructive
      ? `<div class="banner">⚠ Destructive checks were ENABLED for this run (scope + CLI both authorized).</div>`
      : ""
  }

  <div class="banner" style="background:${d.activeInjection ? "#0f2f1f" : "#1a2230"};border-color:${
    d.activeInjection ? "#2f9e6b" : "#3a5170"
  };color:${d.activeInjection ? "#c6ffe0" : "#aecbe6"}">
    ${
      d.activeInjection
        ? "Active injection testing was PERFORMED: dalfox (XSS) and sqlmap (SQLi) against in-scope parameters."
        : "Active injection testing (SQLi/XSS via sqlmap/dalfox) was NOT performed — the destructive gate was closed. Re-run with scope allow_destructive: true and --allow-destructive to include it."
    }
  </div>

  <div class="meta">
    <div><div class="k">Client</div><div class="v">${esc(d.scope.client ?? "—")}</div></div>
    <div><div class="k">Engagement</div><div class="v">${esc(d.scope.name)}</div></div>
    <div><div class="k">Authorized by</div><div class="v">${esc(d.scope.authorizedBy)}</div></div>
    <div><div class="k">Authorization ref</div><div class="v">${esc(d.scope.authorizationRef)}</div></div>
    <div><div class="k">Scope hash</div><div class="v">${esc(d.scope.scopeHash.slice(0, 24))}…</div></div>
    <div><div class="k">Triggered by</div><div class="v">${esc(d.actor)}</div></div>
    <div><div class="k">Assets discovered</div><div class="v">${esc(d.assetCount)}</div></div>
    <div><div class="k">Started</div><div class="v">${esc(d.startedAt)}</div></div>
    <div><div class="k">Finished</div><div class="v">${esc(d.finishedAt)}</div></div>
  </div>

  ${coverageSection(d.coverage)}

  ${d.retest ? retestSection(d.retest) : ""}

  <h2>Severity summary</h2>
  <div class="cards">${summaryCards(d.severityCounts)}</div>

  <h2>Findings ${dojoLink ? `<span style="text-transform:none;float:right;font-size:13px">${dojoLink}</span>` : ""}</h2>
  <table>
    <thead><tr><th style="width:90px">Severity</th><th>Finding</th><th style="width:180px">Target</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>

  <footer>
    Generated ${esc(d.generatedAt)} by Cytadel Sentinel. Findings storage, dedupe, and triage are managed in DefectDojo.
    This report covers only assets explicitly authorized in scope <strong>${esc(d.scope.name)}</strong>
    (${esc(d.scope.authorizationRef)}).
  </footer>
</div>
</body>
</html>`;
}
