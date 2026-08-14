import path from "node:path";
import { mkdir } from "node:fs/promises";

/** Filesystem layout for run artifacts. */

export const REPORTS_ROOT = path.resolve(process.cwd(), "reports");

export function runDir(runId: string): string {
  return path.join(REPORTS_ROOT, runId);
}

/** Native tool output files (imported into DefectDojo + parsed by normalize). */
export function rawDir(runId: string): string {
  return path.join(runDir(runId), "raw");
}

/** Downloaded JS assets for retire.js. */
export function jsDir(runId: string): string {
  return path.join(rawDir(runId), "js");
}

export async function ensureRunDirs(runId: string): Promise<void> {
  await mkdir(rawDir(runId), { recursive: true });
  await mkdir(jsDir(runId), { recursive: true });
}
