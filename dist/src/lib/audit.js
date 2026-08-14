import { appendFile, mkdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import os from "node:os";
import { Prisma } from "@prisma/client";
import { prisma } from "../db/client.js";
import { logger } from "./logger.js";
const AUDIT_DIR = path.resolve(process.cwd(), "audit");
/** Resolve the acting identity (env override, else OS user). */
export function currentActor() {
    const fromEnv = process.env.SENTINEL_ACTOR?.trim();
    if (fromEnv)
        return fromEnv;
    try {
        return os.userInfo().username;
    }
    catch {
        return "unknown";
    }
}
/** Stable sha256 of any JSON-serializable value (used for scope hashing). */
export function sha256Of(value) {
    const canonical = canonicalJson(value);
    return createHash("sha256").update(canonical).digest("hex");
}
/** Deterministic JSON with sorted keys, so equal scopes hash equally. */
function canonicalJson(value) {
    if (value === null || typeof value !== "object")
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(canonicalJson).join(",")}]`;
    const obj = value;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}
/**
 * Record one audit event. Writes JSONL first (cheap, always available), then
 * the DB. A DB failure is logged but never throws — losing the pipeline over an
 * audit write would be worse than a degraded-but-flagged trail. The JSONL line
 * is the tamper-evident source of record.
 */
export async function audit(event) {
    const actor = event.actor ?? currentActor();
    const timestamp = new Date().toISOString();
    const record = { timestamp, actor, ...event };
    // 1) Append-only JSONL sidecar.
    try {
        await mkdir(AUDIT_DIR, { recursive: true });
        await appendFile(path.join(AUDIT_DIR, "audit.jsonl"), JSON.stringify(record) + "\n", "utf8");
    }
    catch (err) {
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
                tools: (event.tools ?? Prisma.JsonNull),
                detail: (event.detail ?? Prisma.JsonNull),
            },
        });
    }
    catch (err) {
        logger.error({ err, action: event.action }, "audit: DB write failed (JSONL retained)");
    }
    logger.info({ action: event.action, actor, runId: event.runId, target: event.target }, "audit");
}
//# sourceMappingURL=audit.js.map