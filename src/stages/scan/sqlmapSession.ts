import path from "node:path";
import { readdir } from "node:fs/promises";
import type { Dirent } from "node:fs";
import { createHash } from "node:crypto";
import { run } from "../../lib/exec.js";
import type { GenericFinding } from "./generic.js";

/**
 * Fallback sqlmap result reader: session.sqlite.
 *
 * sqlmap stores confirmed injections in `<output-dir>/<host>/session.sqlite`
 * (table `storage`, base64-encoded serialized data) — NOT in the log file or the
 * results CSV. When stdout capture yields nothing, we read the session as a
 * backup: base64-decode the storage values and scrape the readable technique
 * titles + payloads that survive serialization, then emit one finding per
 * confirmed technique. Best-effort by design; the primary source is stdout.
 *
 * Uses the system `sqlite3` CLI (spawned via the safe exec wrapper — the DB path
 * is the only argument; no target data is interpolated into a shell string).
 */

/** Recursively locate the first session.sqlite under a directory. */
export async function findSessionFile(rootDir: string): Promise<string | null> {
  let entries: Dirent[];
  try {
    entries = await readdir(rootDir, { withFileTypes: true });
  } catch {
    return null;
  }
  for (const e of entries) {
    const full = path.join(rootDir, e.name);
    if (e.isDirectory()) {
      const nested = await findSessionFile(full);
      if (nested) return nested;
    } else if (e.name === "session.sqlite") {
      return full;
    }
  }
  return null;
}

/** Dump the base64 `storage` values, decoded to a single latin1 text blob. */
async function dumpSessionText(sessionFile: string): Promise<string> {
  try {
    const { stdout } = await run("sqlite3", ["-readonly", sessionFile, "SELECT value FROM storage;"], {
      allowNonZeroExit: true,
      timeoutMs: 15_000,
    });
    const decoded: string[] = [];
    for (const line of stdout.split(/\r?\n/)) {
      const v = line.trim();
      if (!v) continue;
      try {
        decoded.push(Buffer.from(v, "base64").toString("latin1"));
      } catch {
        decoded.push(v);
      }
    }
    return decoded.join("\n");
  } catch {
    return "";
  }
}

const DBMS_RE =
  /\b(SQLite|MySQL|PostgreSQL|Microsoft SQL Server|Microsoft Access|Oracle|Firebird|IBM DB2|SAP MaxDB|Sybase|HSQLDB|H2)\b/i;

// Human-readable technique labels sqlmap stores in each injection's title.
const TECHNIQUES: ReadonlyArray<{ key: string; label: string; re: RegExp }> = [
  { key: "boolean", label: "boolean-based blind", re: /boolean-based blind/i },
  { key: "time", label: "time-based blind", re: /time-based blind/i },
  { key: "error", label: "error-based", re: /error-based/i },
  { key: "union", label: "UNION query", re: /UNION query|UNION-based/i },
  { key: "stacked", label: "stacked queries", re: /stacked queries/i },
  { key: "inline", label: "inline query", re: /inline query/i },
];

/** Derive the injected parameter from the URL query names that appear in the blob. */
function deriveParam(url: string, blob: string): string | null {
  try {
    const u = new URL(url.includes("://") ? url : `http://${url}`);
    for (const name of u.searchParams.keys()) {
      if (new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}=`).test(blob)) return name;
    }
    // Fall back to the first query param if none matched textually.
    const first = [...u.searchParams.keys()][0];
    return first ?? null;
  } catch {
    return null;
  }
}

/** Extract candidate SQLi payloads (readable substrings) from the decoded blob. */
function extractPayloads(blob: string, param: string | null): string[] {
  const out = new Set<string>();
  const anchor = param ? param.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") : "[A-Za-z0-9_]+";
  // "<param>=<value with SQL syntax>" over PRINTABLE ASCII only — payloads carry
  // quotes/parens, and the printable class stops cleanly at the pickle framing
  // bytes (>0x7e) that separate stored fields.
  const re = new RegExp(
    `${anchor}=[\\x20-\\x7e]{0,200}?(?:AND|OR|UNION|SELECT|SLEEP|RANDOMBLOB|LIKE|WAITFOR|;|--)[\\x20-\\x7e]{0,200}`,
    "gi",
  );
  for (const m of blob.matchAll(re)) {
    const s = m[0].trim();
    if (s.length > 4) out.add(s);
    if (out.size >= 8) break;
  }
  return [...out];
}

/**
 * Parse a decoded session text blob into findings — pure and unit-testable.
 * One finding per technique whose readable title survived serialization.
 */
export function extractInjectionsFromSessionText(blob: string, url: string): GenericFinding[] {
  if (!blob) return [];
  const dbms = blob.match(DBMS_RE)?.[1] ?? null;
  const param = deriveParam(url, blob);
  const payloads = extractPayloads(blob, param);
  const paramLabel = param ?? "(unknown)";

  const findings: GenericFinding[] = [];
  for (const tech of TECHNIQUES) {
    if (!tech.re.test(blob)) continue;
    const evidenceParts = [`technique: ${tech.label}`];
    if (payloads.length) evidenceParts.push(`payload: ${payloads.join(" | ")}`);
    if (dbms) evidenceParts.push(`DBMS: ${dbms}`);
    findings.push({
      sourceTool: "sqlmap",
      title: `SQL Injection (${tech.label}) on parameter "${paramLabel}"`,
      description:
        `sqlmap confirmed ${tech.label} SQL injection on parameter "${paramLabel}"` +
        `${dbms ? ` — back-end DBMS: ${dbms}` : ""} (recovered from session.sqlite).`,
      severity: "HIGH",
      cwe: 89,
      endpoint: url,
      uniqueId: createHash("sha256").update(`sqlmap|${url}|${paramLabel}|${tech.key}`).digest("hex").slice(0, 32),
      evidence: evidenceParts.join(" — "),
    });
  }
  return findings;
}

/**
 * Read a target's session.sqlite (if present) and return recovered findings.
 * Returns [] when no session file, no sqlite3, or nothing decodable.
 */
export async function readSqlmapSessionFindings(outDir: string, url: string): Promise<GenericFinding[]> {
  const sessionFile = await findSessionFile(outDir);
  if (!sessionFile) return [];
  const blob = await dumpSessionText(sessionFile);
  return extractInjectionsFromSessionText(blob, url);
}
