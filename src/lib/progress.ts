import { LIMITS } from "../config/limits.js";
import type { RunContext } from "../core/context.js";
import type { StageId } from "../core/events.js";

/**
 * Periodic progress heartbeat for long-running tools. Emits a stage:status
 * event (and a file log line) every LIMITS.progressIntervalMs so the reporter
 * can show "nuclei · 4m elapsed" instead of a silent spinner, and CI/file logs
 * record forward progress.
 */

export interface Heartbeat {
  stop(): void;
}

export interface HeartbeatOptions {
  intervalMs?: number;
  /** Total unit count (e.g. targets) to render "done/total". */
  total?: number;
  /** Live getter for completed units, when the caller loops per-target. */
  getDone?: () => number;
}

function humanElapsed(ms: number): string {
  const totalSec = Math.floor(ms / 1000);
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  if (m > 0) return s > 0 ? `${m}m ${s}s` : `${m}m`;
  return `${s}s`;
}

export function startHeartbeat(
  ctx: RunContext,
  stage: StageId,
  tool: string,
  opts: HeartbeatOptions = {},
): Heartbeat {
  const startedAt = Date.now();
  const intervalMs = opts.intervalMs ?? LIMITS.progressIntervalMs;

  const tick = (): void => {
    const elapsedMs = Date.now() - startedAt;
    let text = `${tool} · ${humanElapsed(elapsedMs)} elapsed`;
    if (opts.total !== undefined) {
      const done = opts.getDone ? opts.getDone() : 0;
      text += ` · ${done}/${opts.total}`;
    }
    ctx.bus.stageStatus(stage, text);
    ctx.log.info({ tool, stage, elapsedMs, ...(opts.total !== undefined ? { total: opts.total } : {}) }, "tool progress");
  };

  const timer = setInterval(tick, intervalMs);
  // Never keep the process alive just for the heartbeat.
  if (typeof timer.unref === "function") timer.unref();

  return {
    stop(): void {
      clearInterval(timer);
    },
  };
}
