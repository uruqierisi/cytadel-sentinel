const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEVERITY_COLOR = {
    CRITICAL: "#e0245e",
    HIGH: "#f66d3b",
    MEDIUM: "#f5b301",
    LOW: "#2fa7ff",
    INFO: "#7a8699",
};
function esc(v) {
    return String(v ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}
function severityBadge(sev) {
    return `<span class="sev" style="background:${SEVERITY_COLOR[sev]}">${sev}</span>`;
}
function summaryCards(counts) {
    return SEVERITY_ORDER.map((sev) => `
      <div class="card" style="--accent:${SEVERITY_COLOR[sev]}">
        <div class="card-num">${counts[sev] ?? 0}</div>
        <div class="card-label">${sev}</div>
      </div>`).join("");
}
function findingRow(f) {
    const flags = [
        f.verified ? '<span class="tag verified">verified</span>' : "",
        f.active ? "" : '<span class="tag inactive">inactive</span>',
    ]
        .filter(Boolean)
        .join(" ");
    return `
    <tr>
      <td>${severityBadge(f.severity)}</td>
      <td>
        <div class="f-title">${esc(f.title)} ${flags}</div>
        <div class="f-meta">${esc(f.sourceTool)}${f.cve ? " · " + esc(f.cve) : ""}${f.cvss != null ? " · CVSS " + esc(f.cvss) : ""}</div>
        ${f.description ? `<div class="f-desc">${esc(f.description).slice(0, 600)}</div>` : ""}
        ${f.evidence ? `<pre class="f-evidence">${esc(f.evidence).slice(0, 1200)}</pre>` : ""}
      </td>
      <td class="f-target">${esc(f.target)}</td>
    </tr>`;
}
const LOGO = `
<svg width="42" height="42" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M32 3l24 9v16c0 15-10 27-24 33C18 55 8 43 8 28V12l24-9z" fill="#0b1f3a" stroke="#28e0c8" stroke-width="2.5"/>
  <path d="M32 16l14 5v9c0 9-6 16-14 20-8-4-14-11-14-20v-9l14-5z" fill="#122c4f"/>
  <path d="M24 33l6 6 12-14" stroke="#28e0c8" stroke-width="3.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;
export function renderHtml(d) {
    const rows = d.findings.length
        ? d.findings.map(findingRow).join("")
        : `<tr><td colspan="3" class="empty">No findings reported for this engagement.</td></tr>`;
    const dojoLink = d.defectDojoUrl && d.engagementId
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
      <div class="sub">Authorized web-application penetration test · Run ${esc(d.runId)}</div>
    </div>
  </header>

  ${d.scope.allowDestructive
        ? `<div class="banner">⚠ Destructive checks were ENABLED for this run (scope + CLI both authorized).</div>`
        : ""}

  <div class="meta">
    <div><div class="k">Scope</div><div class="v">${esc(d.scope.name)}</div></div>
    <div><div class="k">Authorized by</div><div class="v">${esc(d.scope.authorizedBy)}</div></div>
    <div><div class="k">Authorization ref</div><div class="v">${esc(d.scope.authorizationRef)}</div></div>
    <div><div class="k">Scope hash</div><div class="v">${esc(d.scope.scopeHash.slice(0, 24))}…</div></div>
    <div><div class="k">Triggered by</div><div class="v">${esc(d.actor)}</div></div>
    <div><div class="k">Assets discovered</div><div class="v">${esc(d.assetCount)}</div></div>
    <div><div class="k">Started</div><div class="v">${esc(d.startedAt)}</div></div>
    <div><div class="k">Finished</div><div class="v">${esc(d.finishedAt)}</div></div>
  </div>

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
//# sourceMappingURL=template.js.map