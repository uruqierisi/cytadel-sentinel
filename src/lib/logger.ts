import fs from "node:fs";
import path from "node:path";
import pino from "pino";
import { PRETTY_MODE } from "./mode.js";

/**
 * The FILE/structured-log channel (separate from the human CONSOLE channel in
 * ui.ts, and separate again from the compliance audit trail in audit.ts).
 *
 * Sink selection:
 *   - PRETTY mode  -> logs/sentinel.log  (terminal stays clean; the reporter
 *                     draws the UI). LOG_LEVEL controls this FILE log's verbosity.
 *   - JSON/CI mode -> stdout as raw JSON lines (for piping / CI).
 *
 * The audit JSONL sidecar (audit/audit.jsonl) is unaffected by any of this — it
 * is written directly in audit.ts and remains byte-for-byte the compliance record.
 */

const level = process.env.LOG_LEVEL ?? "info";

function fileDestination(): pino.DestinationStream {
  const dir = path.resolve(process.cwd(), "logs");
  fs.mkdirSync(dir, { recursive: true });
  // sync:true so a short-lived CLI process never loses trailing log lines on exit.
  return pino.destination({ dest: path.join(dir, "sentinel.log"), append: true, sync: true });
}

const destination = PRETTY_MODE ? fileDestination() : pino.destination(1); // fd 1 = stdout

export const logger = pino({ level }, destination);

/** Child logger bound to a run id so every line is correlatable. */
export function runLogger(runId: string) {
  return logger.child({ runId });
}
