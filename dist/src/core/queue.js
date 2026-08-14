import { Queue, Worker, QueueEvents } from "bullmq";
import { Redis } from "ioredis";
import { logger } from "../lib/logger.js";
import { contextForJob } from "./run.js";
import { executePipeline } from "./orchestrator.js";
/**
 * BullMQ job queue. Scans are long-running, so pipeline execution is modeled as
 * a durable job. `sentinel run` enqueues a job; a Worker (in-process by default,
 * or a standalone `sentinel worker`) executes the pipeline.
 */
export const QUEUE_NAME = "sentinel-runs";
function connection() {
    const url = process.env.REDIS_URL ?? "redis://localhost:6379";
    // maxRetriesPerRequest must be null for BullMQ blocking commands.
    return new Redis(url, { maxRetriesPerRequest: null });
}
let queueSingleton = null;
export function getQueue() {
    if (!queueSingleton) {
        queueSingleton = new Queue(QUEUE_NAME, { connection: connection() });
    }
    return queueSingleton;
}
/** Enqueue a run job. Returns the BullMQ job id. */
export async function enqueueRunJob(data) {
    const job = await getQueue().add("run", data, {
        jobId: data.runId, // 1:1 with the Run row
        removeOnComplete: false,
        removeOnFail: false,
        attempts: 1, // do NOT auto-retry active scanning
    });
    logger.info({ jobId: job.id, runId: data.runId }, "queued run job");
    return job.id ?? data.runId;
}
/** The job processor: rebuild context + run the pipeline. */
async function processor(job) {
    const ctx = await contextForJob(job.data);
    return executePipeline(ctx);
}
/** Start a worker. Caller is responsible for closing it. */
export function startWorker() {
    const worker = new Worker(QUEUE_NAME, processor, {
        connection: connection(),
        concurrency: 1, // one active scan at a time by default
    });
    worker.on("completed", (job) => logger.info({ jobId: job.id }, "run job completed"));
    worker.on("failed", (job, err) => logger.error({ jobId: job?.id, err }, "run job failed"));
    return worker;
}
/**
 * Enqueue a run and process it to completion in this process (Phase-1 on-demand
 * UX). Spins an ephemeral worker, waits for the job, and returns the outcome.
 */
export async function runInline(data) {
    const queue = getQueue();
    const events = new QueueEvents(QUEUE_NAME, { connection: connection() });
    await events.waitUntilReady();
    const worker = startWorker();
    try {
        const job = await queue.add("run", data, { jobId: data.runId, attempts: 1 });
        const outcome = (await job.waitUntilFinished(events));
        return outcome;
    }
    finally {
        await worker.close();
        await events.close();
    }
}
/** Clean shutdown of the shared queue connection. */
export async function closeQueue() {
    if (queueSingleton) {
        await queueSingleton.close();
        queueSingleton = null;
    }
}
//# sourceMappingURL=queue.js.map