import { appendFile, mkdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import os from "node:os";
import { Prisma } from "@prisma/client";
import { prisma } from "../db/client.js";
import { logger } from "./logger.js";

/**
 * Append-only audit trail.
 *
 * NON-NEGOTIABLE RULE: every run records who triggered it, timestamp, scope
 * hash, tools+versions used, and every target touched — and every scope
 * decision. This module is the single choke point for that.
 *
 * Durability: each event is written BOTH to Postgres (AuditLog) and to an
 * append-only JSONL sidecar under audit/. The two are cross-checkable; the
 * JSONL survives even if the DB is unavailable. Nothing here ever updates or
 * deletes a prior record.
 */

export type AuditAction =
  | "RUN_START"
  | "RUN_COMPLETE"
  | "RUN_FAILED"
  | "SCOPE_LOAD"
  | "SCOPE_ACCEPT"
  | "SCOPE_REJECT"
  | "STAGE_START"
  | "STAGE_COMPLETE"
  | "TOOL_EXEC"
  | "TARGET_TOUCHED"
  | "IMPORT"
  | "REPORT"
  | "DESTRUCTIVE_GATE";

export interface AuditEvent {
  runId?: string;
  actor?: string;
  action: AuditAction;
  scopeHash?: string;
  target?: string;
  tools?: Record<string, string>;
  detail?: Record<string, unknown>;
}

const AUDIT_DIR = path.resolve(process.cwd(), "audit");

/** Resolve the acting identity (env override, else OS user). */
export function currentActor(): string {
  const fromEnv = process.env.SENTINEL_ACTOR?.trim();
  if (fromEnv) return fromEnv;
  try {
    return os.userInfo().username;
  } catch {
    return "unknown";
  }
}

/** Stable sha256 of any JSON-serializable value (used for scope hashing). */
export function sha256Of(value: unknown): string {
  const canonical = canonicalJson(value);
  return createHash("sha256").update(canonical).digest("hex");
}

/** Deterministic JSON with sorted keys, so equal scopes hash equally. */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

/**
 * Record one audit event. Writes JSONL first (cheap, always available), then
 * the DB. A DB failure is logged but never throws — losing the pipeline over an
 * audit write would be worse than a degraded-but-flagged trail. The JSONL line
 * is the tamper-evident source of record.
 */
export async function audit(event: AuditEvent): Promise<void> {
  const actor = event.actor ?? currentActor();
  const timestamp = new Date().toISOString();
  const record = { timestamp, actor, ...event };

  // 1) Append-only JSONL sidecar.
  try {
    await mkdir(AUDIT_DIR, { recursive: true });
    await appendFile(
      path.join(AUDIT_DIR, "audit.jsonl"),
      JSON.stringify(record) + "\n",
      "utf8",
    );
  } catch (err) {
    logger.error({ err }, "audit: JSONL append failed");
  }

  // 2) Postgres append-only row.
  try {
    await prisma.auditLog.create({
      data: {
        runId: event.runId ?? null,
        actor,
        action: event.action,
        scopeHash: event.scopeHash ?? null,
        target: event.target ?? null,
        tools: (event.tools ?? Prisma.JsonNull) as Prisma.InputJsonValue,
        detail: (event.detail ?? Prisma.JsonNull) as Prisma.InputJsonValue,
      },
    });
  } catch (err) {
    logger.error({ err, action: event.action }, "audit: DB write failed (JSONL retained)");
  }

  logger.info(
    { action: event.action, actor, runId: event.runId, target: event.target },
    "audit",
  );
}
