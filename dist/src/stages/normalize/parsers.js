import { parseJsonl } from "../../lib/parse.js";
import { normalizeSeverity } from "./types.js";
/**
 * Per-tool parsers: native output -> UnifiedFinding[]. These feed the local
 * lightweight Finding table + dedupe. DefectDojo remains the authoritative
 * parser for its own storage; this is a parallel, minimal read.
 */
// --------------------------------------------------------------- nuclei ------
export function parseNuclei(content) {
    return parseJsonl(content).map((r) => {
        const info = (r["info"] ?? {});
        const classification = (info["classification"] ?? {});
        const cvss = typeof classification["cvss-score"] === "number" ? classification["cvss-score"] : null;
        const target = String(r["host"] ?? r["matched-at"] ?? r["url"] ?? "");
        return {
            sourceTool: "nuclei",
            templateId: r["template-id"] ?? null,
            name: String(info["name"] ?? r["template-id"] ?? "nuclei finding"),
            target,
            matchedLocation: r["matched-at"] ?? null,
            severity: normalizeSeverity(info["severity"]),
            cvss,
            epss: typeof r["epss"] === "number" ? r["epss"] : null,
            evidence: buildNucleiEvidence(r),
            raw: r,
        };
    });
}
function buildNucleiEvidence(r) {
    const parts = [];
    if (r["matcher-name"])
        parts.push(`matcher=${r["matcher-name"]}`);
    if (Array.isArray(r["extracted-results"]))
        parts.push(`extracted=${r["extracted-results"].join(",")}`);
    if (r["curl-command"])
        parts.push(String(r["curl-command"]));
    return parts.length ? parts.join(" | ") : null;
}
// ------------------------------------------------------------- retire.js -----
export function parseRetire(content) {
    let doc;
    try {
        doc = JSON.parse(content);
    }
    catch {
        return [];
    }
    // retire json v2/v3: { data: [ { file, results: [ { component, version, vulnerabilities: [...] } ] } ] }
    const files = Array.isArray(doc?.data) ? doc.data : Array.isArray(doc) ? doc : [];
    const out = [];
    for (const f of files) {
        const file = String(f?.file ?? "");
        for (const res of f?.results ?? []) {
            const component = res?.component ?? "library";
            const version = res?.version ?? "?";
            for (const v of res?.vulnerabilities ?? []) {
                const cves = v?.identifiers?.CVE ?? [];
                out.push({
                    sourceTool: "retirejs",
                    templateId: cves[0] ?? `${component}@${version}`,
                    name: `${component} ${version}: ${v?.identifiers?.summary ?? "known vulnerability"}`,
                    target: file,
                    matchedLocation: file,
                    severity: normalizeSeverity(v?.severity),
                    cvss: null,
                    epss: null,
                    evidence: cves.length ? cves.join(", ") : (v?.info ?? []).join(" "),
                    raw: { component, version, vulnerability: v, file },
                });
            }
        }
    }
    return out;
}
// -------------------------------------------------------------- testssl ------
export function parseTestssl(content) {
    const rows = parseCsv(content);
    if (rows.length === 0)
        return [];
    const header = rows[0].map((h) => h.toLowerCase());
    const idx = (name) => header.indexOf(name);
    const iId = idx("id");
    const iFqdn = idx("fqdn/ip");
    const iPort = idx("port");
    const iSev = idx("severity");
    const iFinding = idx("finding");
    const iCve = idx("cve");
    const out = [];
    for (const row of rows.slice(1)) {
        const sevRaw = (row[iSev] ?? "").toUpperCase();
        // Skip non-issues to keep the finding table meaningful.
        if (sevRaw === "OK" || sevRaw === "INFO" || sevRaw === "" || sevRaw === "DEBUG")
            continue;
        const host = row[iFqdn] ?? "";
        const port = row[iPort] ?? "";
        out.push({
            sourceTool: "testssl",
            templateId: row[iId] ?? null,
            name: `TLS: ${row[iId] ?? "issue"}`,
            target: port ? `${host}:${port}` : host,
            matchedLocation: `${host}:${port}`,
            severity: mapTestsslSeverity(sevRaw),
            cvss: null,
            epss: null,
            evidence: row[iFinding] ?? null,
            raw: { id: row[iId], finding: row[iFinding], cve: row[iCve], severity: sevRaw },
        });
    }
    return out;
}
function mapTestsslSeverity(s) {
    switch (s) {
        case "CRITICAL":
            return "CRITICAL";
        case "HIGH":
            return "HIGH";
        case "MEDIUM":
            return "MEDIUM";
        case "LOW":
        case "WARN":
        default:
            return "LOW";
    }
}
// ---------------------------------------------------------------- nikto ------
export function parseNikto(content) {
    // Lightweight XML read: DefectDojo does the authoritative parse. We extract
    // <item> blocks and the enclosing host for a minimal local record.
    const hostMatch = content.match(/targethostname="([^"]*)"/i) ?? content.match(/targetip="([^"]*)"/i);
    const host = hostMatch?.[1] ?? "";
    const items = [...content.matchAll(/<item[^>]*>([\s\S]*?)<\/item>/gi)];
    const out = [];
    for (const m of items) {
        const block = m[1] ?? "";
        const osvdb = m[0].match(/osvdbid="([^"]*)"/i)?.[1] ?? null;
        const uri = block.match(/<uri>([\s\S]*?)<\/uri>/i)?.[1]?.trim() ?? "";
        const desc = block.match(/<description>([\s\S]*?)<\/description>/i)?.[1]?.trim() ?? "nikto item";
        out.push({
            sourceTool: "nikto",
            templateId: osvdb ? `osvdb-${osvdb}` : null,
            name: `Nikto: ${desc.slice(0, 120)}`,
            target: host,
            matchedLocation: uri || host,
            severity: "LOW", // nikto items are server-info/hardening class by default
            cvss: null,
            epss: null,
            evidence: desc,
            raw: { osvdb, uri, description: desc },
        });
    }
    return out;
}
// ------------------------------------------------------------- csv util ------
/** Minimal CSV parser handling quoted fields and embedded commas/quotes. */
export function parseCsv(content) {
    const rows = [];
    for (const rawLine of content.split(/\r?\n/)) {
        if (rawLine.trim() === "")
            continue;
        const fields = [];
        let cur = "";
        let inQuotes = false;
        for (let i = 0; i < rawLine.length; i++) {
            const ch = rawLine[i];
            if (inQuotes) {
                if (ch === '"' && rawLine[i + 1] === '"') {
                    cur += '"';
                    i++;
                }
                else if (ch === '"') {
                    inQuotes = false;
                }
                else {
                    cur += ch;
                }
            }
            else if (ch === '"') {
                inQuotes = true;
            }
            else if (ch === ",") {
                fields.push(cur);
                cur = "";
            }
            else {
                cur += ch;
            }
        }
        fields.push(cur);
        rows.push(fields);
    }
    return rows;
}
//# sourceMappingURL=parsers.js.map