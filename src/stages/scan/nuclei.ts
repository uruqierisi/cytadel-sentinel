import { writeFile } from "node:fs/promises";
import path from "node:path";
import { run } from "../../lib/exec.js";
import { audit } from "../../lib/audit.js";
import { rawDir } from "../../lib/paths.js";
import { readFileIfNonEmpty } from "../../lib/files.js";
import { mergeJsonlLines } from "../../lib/parse.js";
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
  const bin = ctx.tools.pathFor("nuclei");
  if (!bin) {
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
    const res = await run(bin, args, {
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

  // MERGE the -o file with captured stdout: on SIGTERM the file holds only the
  // flushed lines while stdout holds the tail. Merging + deduping keeps EVERY
  // emitted finding (the WAF/tech/iis lines that were in stdout but not the file).
  const fileContent = (await readFileIfNonEmpty(outPath)) ?? "";
  const merged = mergeJsonlLines([fileContent, stdout]);

  if (merged.length === 0) {
    ctx.log.warn({ outPath }, "scan: nuclei produced no output");
    return null;
  }

  // Rewrite the file with the complete, deduped set so Normalize + DefectDojo
  // import see every captured finding.
  await writeFile(outPath, merged + "\n", "utf8");
  const lineCount = merged.split("\n").length;

  if (timedOut) {
    ctx.log.warn({ outPath, lines: lineCount }, "scan: nuclei PARTIAL (timed out) — merged file+stdout");
    ctx.bus.stageProgress("scan", `nuclei timed out — kept ${lineCount} finding line(s)`, false);
  } else {
    ctx.log.info({ outPath, lines: lineCount }, "scan: nuclei complete");
  }

  return { tool: "nuclei", dojoScanType: "Nuclei Scan", filePath: outPath, format: "jsonl", target: "aggregate" };
}
