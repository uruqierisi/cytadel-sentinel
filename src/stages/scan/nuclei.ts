import { writeFile } from "node:fs/promises";
import path from "node:path";
import { run, toolExists } from "../../lib/exec.js";
import { audit } from "../../lib/audit.js";
import { rawDir } from "../../lib/paths.js";
import { readFileIfNonEmpty } from "../../lib/files.js";
import { LIMITS } from "../../config/limits.js";
import { startHeartbeat } from "../../lib/progress.js";
import type { RunContext } from "../../core/context.js";
import type { ScanArtifact } from "./artifacts.js";

/**
 * nuclei — templated web/cve/misconfig/exposure/tech checks over alive in-scope
 * URLs.
 *
 * Targets are fed via stdin (never a shell string). Auth headers are injected so
 * scanning goes past login. Rate limited per scope, with per-request timeout /
 * retry / concurrency caps so a scan cannot run unbounded.
 *
 * PARTIAL CAPTURE: nuclei writes incrementally to `-o nuclei.jsonl`. If nuclei is
 * killed at the timeout (SIGTERM), we STILL read whatever landed on disk (or the
 * captured stdout) and hand it to Normalize — valid findings are never discarded.
 */
export async function runNuclei(ctx: RunContext, urls: string[]): Promise<ScanArtifact | null> {
  if (urls.length === 0) return null;
  if (!(await toolExists("nuclei", ["-version"]))) {
    ctx.log.warn("scan: nuclei not installed — skipping");
    return null;
  }

  const outPath = path.join(rawDir(ctx.runId), "nuclei.jsonl");
  const args = [
    "-jsonl",
    "-o", // incremental write-to-disk so a kill still leaves findings behind
    outPath,
    "-silent",
    "-no-color",
    "-tags",
    LIMITS.nuclei.tags,
    // Speed caps.
    "-rate-limit",
    String(ctx.scope.rate_limit_rps),
    "-timeout",
    String(LIMITS.nuclei.requestTimeoutSec),
    "-retries",
    String(LIMITS.nuclei.retries),
    "-concurrency",
    String(LIMITS.nuclei.concurrency),
    "-max-host-error",
    String(LIMITS.nuclei.maxHostError),
  ];
  for (const line of ctx.auth.headerLines) {
    args.push("-H", line);
  }
  if (!ctx.allowDestructive) {
    // Belt-and-suspenders: exclude template tags that can mutate state.
    args.push("-exclude-tags", "dos,fuzz,intrusive,sqli-blind");
  }

  await audit({
    runId: ctx.runId,
    actor: ctx.actor,
    action: "TOOL_EXEC",
    scopeHash: ctx.scopeHash,
    detail: { tool: "nuclei", stage: "scan", targets: urls.length, allowDestructive: ctx.allowDestructive },
  });

  const hb = startHeartbeat(ctx, "scan", "nuclei", { total: urls.length });
  let timedOut = false;
  let stdout = "";
  try {
    const res = await run("nuclei", args, {
      input: urls.join("\n") + "\n",
      allowNonZeroExit: true,
      tolerateTimeout: true, // killed -> partial, not thrown away
      timeoutMs: LIMITS.toolTimeoutMs.nuclei,
    });
    timedOut = res.timedOut;
    stdout = res.stdout;
  } catch (err) {
    // Only truly unexpected failures land here (spawn error, etc.). Even then we
    // fall through to read any partial file that exists.
    ctx.log.error({ err }, "scan: nuclei errored — attempting partial capture");
  } finally {
    hb.stop();
  }

  // Prefer the incrementally-written file; fall back to captured stdout.
  let captured = await readFileIfNonEmpty(outPath);
  if (!captured && stdout.trim().length > 0) {
    await writeFile(outPath, stdout, "utf8");
    captured = stdout;
  }

  if (!captured) {
    ctx.log.warn({ outPath }, "scan: nuclei produced no output");
    return null;
  }

  if (timedOut) {
    ctx.log.warn(
      { outPath, bytes: captured.length },
      "scan: nuclei PARTIAL (timed out) — keeping captured findings",
    );
    ctx.bus.stageProgress("scan", `nuclei timed out — kept ${captured.length} bytes of partial findings`, false);
  } else {
    ctx.log.info({ outPath }, "scan: nuclei complete");
  }

  return { tool: "nuclei", dojoScanType: "Nuclei Scan", filePath: outPath, format: "jsonl", target: "aggregate" };
}
