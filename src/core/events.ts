import { EventEmitter } from "node:events";
import type { Severity } from "../stages/normalize/types.js";

/**
 * Run event bus. Stages emit lifecycle events onto this bus; ONE reporter
 * (src/lib/ui.ts) subscribes and renders them. Stage code never writes to the
 * terminal directly — this is the seam that keeps presentation out of the
 * pipeline.
 */

export type StageId = "recon" | "scan" | "normalize" | "import" | "report";

export interface RunStartPayload {
  toolName: string;
  runId: string;
  scopeName: string;
  authMode: string;
  allowDestructive: boolean;
}
export interface StageStartPayload {
  stage: StageId;
  title: string;
}
export interface StageProgressPayload {
  stage: StageId;
  message: string;
  /** Detail lines only shown under --verbose. */
  detail: boolean;
}
export interface StageDonePayload {
  stage: StageId;
  summary: string;
}
export interface StageFailPayload {
  stage: StageId;
  error: string;
}
export interface ScopeSummaryPayload {
  accepted: number;
  total: number;
}
export interface RunDonePayload {
  status: "COMPLETED" | "FAILED";
  reportPath?: string;
  engagementId?: number;
  severity?: Record<Severity, number>;
  error?: string;
}

/**
 * Typed façade over EventEmitter. Stages call the emit-side methods; the
 * reporter calls the on-side methods. Multiple subscribers are allowed.
 */
export class RunBus extends EventEmitter {
  // ---- emit side (called by orchestrator + stages) ----
  runStart(p: RunStartPayload): void {
    this.emit("run:start", p);
  }
  stageStart(stage: StageId, title: string): void {
    this.emit("stage:start", { stage, title });
  }
  stageProgress(stage: StageId, message: string, detail = false): void {
    this.emit("stage:progress", { stage, message, detail });
  }
  stageDone(stage: StageId, summary: string): void {
    this.emit("stage:done", { stage, summary });
  }
  stageFail(stage: StageId, error: string): void {
    this.emit("stage:fail", { stage, error });
  }
  scopeSummary(accepted: number, total: number): void {
    this.emit("scope:summary", { accepted, total });
  }
  runDone(p: RunDonePayload): void {
    this.emit("run:done", p);
  }

  // ---- subscribe side (called by the reporter) ----
  onRunStart(cb: (p: RunStartPayload) => void): void {
    this.on("run:start", cb as (...a: unknown[]) => void);
  }
  onStageStart(cb: (p: StageStartPayload) => void): void {
    this.on("stage:start", cb as (...a: unknown[]) => void);
  }
  onStageProgress(cb: (p: StageProgressPayload) => void): void {
    this.on("stage:progress", cb as (...a: unknown[]) => void);
  }
  onStageDone(cb: (p: StageDonePayload) => void): void {
    this.on("stage:done", cb as (...a: unknown[]) => void);
  }
  onStageFail(cb: (p: StageFailPayload) => void): void {
    this.on("stage:fail", cb as (...a: unknown[]) => void);
  }
  onScopeSummary(cb: (p: ScopeSummaryPayload) => void): void {
    this.on("scope:summary", cb as (...a: unknown[]) => void);
  }
  onRunDone(cb: (p: RunDonePayload) => void): void {
    this.on("run:done", cb as (...a: unknown[]) => void);
  }
}

/**
 * In-process registry so the reporter (created in the CLI) and the pipeline
 * (executed inside the in-process BullMQ worker for `runInline`) can share one
 * bus by run id. Detached/standalone workers simply get a fresh, unsubscribed
 * bus — their events go nowhere and only the file/JSON log records them.
 */
const registry = new Map<string, RunBus>();

export function registerBus(runId: string, bus: RunBus): void {
  registry.set(runId, bus);
}
export function getBus(runId: string): RunBus | undefined {
  return registry.get(runId);
}
export function unregisterBus(runId: string): void {
  registry.delete(runId);
}
