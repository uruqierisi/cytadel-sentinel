import path from "node:path";
import { mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { run } from "../../lib/exec.js";
import { audit } from "../../lib/audit.js";
import { rawDir } from "../../lib/paths.js";
import { LIMITS } from "../../config/limits.js";
import { startHeartbeat } from "../../lib/progress.js";
import { gate, type RunContext } from "../../core/context.js";
import { resolveSqlmap } from "./resolve.js";
import { readSqlmapSessionFindings } from "./sqlmapSession.js";
import { writeGenericFindingsFile, type GenericFinding } from "./generic.js";
import type { HttpMethodU, InjectionCandidate } from "./candidates.js";
import type { ScanArtifact } from "./artifacts.js";

/** Persist the raw captured stdout/stderr next to the run's output for inspection. */
async function persistRawOutput(outDir: string, stdout: string, stderr: string): Promise<void> {
  try {
    await mkdir(outDir, { recursive: true });
    await writeFile(path.join(outDir, "sentinel-stdout.txt"), stdout, "utf8");
    if (stderr) await writeFile(path.join(outDir, "sentinel-stderr.txt"), stderr, "utf8");
  } catch {
    // Non-fatal: raw persistence is a diagnostic aid, not required for findings.
  }
}

/**
 * sqlmap — active SQL injection. DESTRUCTIVE: only invoked when the destructive
 * gate is open.
 *
 * Practical runtime:
 *   - targets are deduped by (path + param NAME) so ?id=1 / ?id=2 count once,
 *     then capped to LIMITS.maxInjectionTargets distinct signatures;
 *   - fast flags: low level/risk, fast techniques only (BEU), threads, batch;
 *   - a HARD per-target exec timeout (not 20 min each) plus an OVERALL wall-clock
 *     budget that stops starting new targets once exceeded;
 *   - partial capture: a killed target still contributes whatever injection
 *     points were confirmed in its stdout.
 */
/**
 * @param signatures ALREADY-deduped injection signatures — the SAME capped list
 *   dalfox receives (see scan/index.ts). Never the raw param URLs.
 */
export async function runSqlmap(ctx: RunContext, candidates: InjectionCandidate[]): Promise<ScanArtifact | null> {
  if (candidates.length === 0) return null;
  const tool = await resolveSqlmap();
  if (!tool) {
    ctx.log.warn("scan: sqlmap not installed — skipping (install via scripts/setup.sh)");
    return null;
  }

  // Input is already deduped + capped upstream. Re-gate defensively.
  const targets: InjectionCandidate[] = [];
  for (const c of candidates) {
    if ((await gate(ctx, c.url)).allowed) targets.push(c);
  }
  if (targets.length === 0) return null;
  ctx.log.info({ signatures: targets.length }, "scan: sqlmap running over deduped signatures");

  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "TOOL_EXEC",
    scopeHash: ctx.scopeHash,
    detail: { tool: "sqlmap", stage: "scan", targets: targets.length, allowDestructive: true },
  });

  const cfg = LIMITS.sqlmap;
  const baseOutDir = path.join(rawDir(ctx.runId), "sqlmap");
  // Build ONE invocation per candidate up front — each with its OWN output dir so
  // same-host targets never overwrite each other's target.txt / session.sqlite.
  const invocations = planSqlmapInvocations(tool.baseArgs, targets, cfg, baseOutDir, {
    cookie: ctx.auth.cookie,
    headerLines: ctx.auth.nonCookieHeaderLines,
  });
  ctx.log.info(
    { targets: invocations.map((i) => i.url) },
    "scan: sqlmap invocations (one -u run per signature, isolated output dir)",
  );

  const findings: GenericFinding[] = [];
  const startedAt = Date.now();
  let done = 0;
  let budgetHit = false;
  const hb = startHeartbeat(ctx, "scan", "sqlmap", { total: invocations.length, getDone: () => done });
  try {
    for (const inv of invocations) {
      // Overall time budget: stop launching new targets once exceeded.
      if (Date.now() - startedAt >= cfg.budgetMs) {
        budgetHit = true;
        ctx.log.warn(
          { done, total: invocations.length, budgetMs: cfg.budgetMs },
          "scan: sqlmap overall budget reached — stopping (keeping findings so far)",
        );
        ctx.bus.stageProgress("scan", `sqlmap budget reached at ${done}/${invocations.length} — kept findings so far`, false);
        break;
      }

      // One visible line per target so all N runs are confirmable.
      ctx.bus.stageProgress("scan", `sqlmap testing ${inv.url}`, false);
      ctx.log.info({ url: inv.url, outDir: inv.outDir }, "scan: sqlmap testing target");
      try {
        const res = await run(tool.file, inv.args, {
          allowNonZeroExit: true,
          tolerateTimeout: true,
          timeoutMs: cfg.targetTimeoutMs,
        });

        // The injection block ("sqlmap identified the following injection
        // point(s)" + Parameter/Type/Title/Payload) prints to stdout; some log
        // lines (incl. "back-end DBMS") can land on stderr. Parse BOTH streams so
        // capture never silently misses the detection. Log lengths so an empty
        // capture is visible in the logs.
        const captured = `${res.stdout ?? ""}\n${res.stderr ?? ""}`;
        ctx.log.info(
          { url: inv.url, stdoutLen: (res.stdout ?? "").length, stderrLen: (res.stderr ?? "").length },
          "scan: sqlmap captured output",
        );
        await persistRawOutput(inv.outDir, res.stdout ?? "", res.stderr ?? "");

        let targetFindings = parseSqlmapStdout(captured, inv.url);

        // Fallback: if stdout/stderr yielded nothing, the detection may still be
        // in session.sqlite (sqlmap serializes confirmed injections there even
        // when the log/CSV are empty). Recover from it.
        if (targetFindings.length === 0) {
          const fromSession = await readSqlmapSessionFindings(inv.outDir, inv.url);
          if (fromSession.length > 0) {
            ctx.log.warn(
              { url: inv.url, recovered: fromSession.length },
              "scan: sqlmap stdout empty — recovered injection(s) from session.sqlite",
            );
            targetFindings = fromSession;
          }
        }
        findings.push(...targetFindings);
        if (res.timedOut) ctx.log.warn({ url: inv.url }, "scan: sqlmap PARTIAL (target timeout) — kept parsed injection points");
      } catch (err) {
        ctx.log.error({ err, url: inv.url }, "scan: sqlmap failed for url");
      }
      done++;
    }
  } finally {
    hb.stop();
  }

  if (findings.length === 0) {
    ctx.log.info({ budgetHit }, "scan: sqlmap found no SQL injection");
    return null;
  }

  const outPath = path.join(rawDir(ctx.runId), "sqlmap.generic.json");
  await writeGenericFindingsFile(outPath, findings);
  ctx.log.info({ outPath, findings: findings.length, done, budgetHit }, "scan: sqlmap complete");
  return { tool: "sqlmap", dojoScanType: "Generic Findings Import", filePath: outPath, format: "json", target: "aggregate" };
}

/** sqlmap speed/depth knobs used to build an invocation. */
export interface SqlmapCfg {
  level: number;
  risk: number;
  technique: string;
  threads: number;
  requestTimeoutSec: number;
  retries: number;
}

export interface SqlmapInvocation {
  url: string;
  outDir: string;
  args: string[];
}

/**
 * Per-target output dir. All signatures share one host (testasp.vulnweb.com), so
 * a single output dir would collide (sqlmap namespaces by host and overwrites
 * target.txt/session per host). A unique dir per target keeps every run isolated.
 */
export function sqlmapTargetOutDir(baseDir: string, url: string, index: number): string {
  const slug = createHash("sha1").update(url).digest("hex").slice(0, 12);
  return path.join(baseDir, `t${index}_${slug}`);
}

/** Auth material + method/body injected into an invocation. */
export interface SqlmapExtra {
  /** Session cookie, injected via sqlmap's native --cookie. */
  cookie?: string | null;
  /** Non-cookie header lines ("Name: value"), injected via -H. */
  headerLines?: string[];
  /** HTTP method; non-GET/POST is passed via --method. */
  method?: HttpMethodU;
  /** Request body for POST/PUT/PATCH — sqlmap tests these params via --data. */
  data?: string | null;
}

/** Build the full sqlmap argv for a SINGLE target URL. */
export function buildSqlmapArgs(
  baseArgs: string[],
  url: string,
  cfg: SqlmapCfg,
  outDir: string,
  extra: SqlmapExtra = {},
): string[] {
  const args = [
    ...baseArgs,
    "-u",
    url,
    "--batch",
    "--disable-coloring",
    `--level=${cfg.level}`,
    `--risk=${cfg.risk}`,
    `--technique=${cfg.technique}`,
    `--threads=${cfg.threads}`,
    `--timeout=${cfg.requestTimeoutSec}`,
    `--retries=${cfg.retries}`,
    // NOTE: --smart is deliberately NOT used. It skips any parameter that fails
    // the basic heuristic before real testing — but blind SQLi (e.g. Juice Shop's
    // ?q=) often fails that heuristic while still being injectable, so --smart
    // produced false negatives ("all tested parameters do not appear injectable").
    // Fresh test every run: never reuse a prior run's cached "not injectable"
    // verdict from session.sqlite, which would cause false negatives.
    "--flush-session",
    `--output-dir=${outDir}`,
  ];
  // Method-aware: a POST/PUT body is fuzzed via --data (sqlmap infers POST);
  // non-GET/POST methods are set explicitly.
  if (extra.data) args.push("--data", extra.data);
  if (extra.method && extra.method !== "GET" && extra.method !== "POST") {
    args.push(`--method=${extra.method}`);
  }
  // Authenticated scanning: cookie via the native flag, other headers via -H.
  if (extra.cookie) args.push("--cookie", extra.cookie);
  for (const line of extra.headerLines ?? []) args.push("-H", line);
  return args;
}

/** Auth material shared across all invocations in a run. */
export interface SqlmapAuth {
  cookie?: string | null;
  headerLines?: string[];
}

/**
 * Plan ONE sqlmap invocation per candidate — each with its own isolated output
 * dir, and method/body applied. Unit-testable without executing sqlmap.
 */
export function planSqlmapInvocations(
  baseArgs: string[],
  candidates: InjectionCandidate[],
  cfg: SqlmapCfg,
  baseOutDir: string,
  auth: SqlmapAuth = {},
): SqlmapInvocation[] {
  return candidates.map((c, index) => {
    const outDir = sqlmapTargetOutDir(baseOutDir, c.url + (c.body ?? ""), index);
    const args = buildSqlmapArgs(baseArgs, c.url, cfg, outDir, {
      cookie: auth.cookie,
      headerLines: auth.headerLines,
      method: c.method,
      data: c.body,
    });
    return { url: c.url, outDir, args };
  });
}

/**
 * Parse sqlmap STDOUT (the authoritative source — detection results go to stdout
 * + session.sqlite, NOT the --output-dir results CSV, which only fills during
 * --dump enumeration). sqlmap prints, after "sqlmap identified the following
 * injection point(s)":
 *
 *   Parameter: q (GET)
 *       Type: boolean-based blind
 *       Title: AND boolean-based blind - WHERE or HAVING clause
 *       Payload: q=apple') AND 1234=1234 AND ('abcd'='abcd
 *
 *       Type: time-based blind
 *       Title: SQLite > 2.0 AND time-based blind
 *       Payload: q=apple') AND 1234=RANDOMBLOB(...) AND ('a'='a
 *   ---
 *   back-end DBMS: SQLite
 *
 * ONE finding per confirmed injection point (per Type block) — a parameter with
 * boolean-based AND time-based blind yields two High findings. Partial capture:
 * if sqlmap is killed mid-block, whatever Type/Title/Payload already printed is
 * still emitted.
 */
interface SqlmapBlock {
  type: string;
  title: string | null;
  payload: string | null;
}

export function parseSqlmapStdout(stdout: string, url: string): GenericFinding[] {
  const lines = stdout.split(/\r?\n/);

  // back-end DBMS is target-wide; last stated value wins.
  let dbms: string | null = null;
  for (const raw of lines) {
    const m = raw.match(/back-end DBMS:\s*(.+?)\s*$/i);
    if (m) dbms = m[1]!.trim();
  }

  const findings: GenericFinding[] = [];
  let param: string | null = null;
  let place: string | null = null;
  let block: SqlmapBlock | null = null;

  const emit = (): void => {
    // Emit as soon as we have a parameter and at least a Type or Payload — this
    // is what keeps a killed-mid-block run from losing the confirmed point.
    if (!param || !block || (!block.type && !block.payload)) {
      block = null;
      return;
    }
    findings.push(makeSqlmapFinding(url, param, place, block, dbms));
    block = null;
  };

  for (const raw of lines) {
    const line = raw.trim();

    const paramMatch = line.match(/^Parameter:\s*(.+?)\s*\(([^)]+)\)\s*$/i);
    if (paramMatch) {
      emit();
      param = paramMatch[1]!.trim();
      place = paramMatch[2]!.trim().toUpperCase();
      continue;
    }
    if (!param) continue;

    const typeMatch = line.match(/^Type:\s*(.+)$/i);
    if (typeMatch) {
      emit(); // a new Type closes the previous block
      block = { type: typeMatch[1]!.trim(), title: null, payload: null };
      continue;
    }
    if (block) {
      const titleMatch = line.match(/^Title:\s*(.+)$/i);
      if (titleMatch) {
        block.title = titleMatch[1]!.trim();
        continue;
      }
      const payloadMatch = line.match(/^Payload:\s*(.+)$/i);
      if (payloadMatch) {
        block.payload = payloadMatch[1]!.trim();
        continue;
      }
    }
  }
  emit();
  return findings;
}

function makeSqlmapFinding(
  url: string,
  param: string,
  place: string | null,
  block: SqlmapBlock,
  dbms: string | null,
): GenericFinding {
  const technique = block.type || "SQL injection";
  const evidenceParts: string[] = [`technique: ${block.title || technique}`];
  if (block.payload) evidenceParts.push(`payload: ${block.payload}`);
  if (dbms) evidenceParts.push(`DBMS: ${dbms}`);

  const description =
    `sqlmap confirmed ${technique} SQL injection on parameter "${param}"` +
    `${place ? ` (${place})` : ""}${dbms ? ` — back-end DBMS: ${dbms}` : ""}.` +
    (block.payload ? ` Payload: ${block.payload}.` : "");

  return {
    sourceTool: "sqlmap",
    title: `SQL Injection (${technique}) on parameter "${param}"`,
    description,
    severity: "HIGH",
    cwe: 89,
    endpoint: url,
    // Include the technique so boolean-based and time-based on the same param
    // stay distinct through dedupe.
    uniqueId: createHash("sha256").update(`sqlmap|${url}|${param}|${technique}`).digest("hex").slice(0, 32),
    evidence: evidenceParts.join(" — "),
  };
}
