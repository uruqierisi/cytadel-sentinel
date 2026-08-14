import { Queue, Worker } from "bullmq";
import { type RunJobData } from "./run.js";
import { type PipelineOutcome } from "./orchestrator.js";
/**
 * BullMQ job queue. Scans are long-running, so pipeline execution is modeled as
 * a durable job. `sentinel run` enqueues a job; a Worker (in-process by default,
 * or a standalone `sentinel worker`) executes the pipeline.
 */
export declare const QUEUE_NAME = "sentinel-runs";
export declare function getQueue(): Queue<RunJobData, PipelineOutcome>;
/** Enqueue a run job. Returns the BullMQ job id. */
export declare function enqueueRunJob(data: RunJobData): Promise<string>;
/** Start a worker. Caller is responsible for closing it. */
export declare function startWorker(): Worker<RunJobData, PipelineOutcome>;
/**
 * Enqueue a run and process it to completion in this process (Phase-1 on-demand
 * UX). Spins an ephemeral worker, waits for the job, and returns the outcome.
 */
export declare function runInline(data: RunJobData): Promise<PipelineOutcome>;
/** Clean shutdown of the shared queue connection. */
export declare function closeQueue(): Promise<void>;
