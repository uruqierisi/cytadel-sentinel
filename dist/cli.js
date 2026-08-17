#!/usr/bin/env node
import { Command } from "commander";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { run as execRun } from "./src/lib/exec.js";
import { loadScope, ScopeValidationError } from "./src/config/scope.js";
import { evaluateScope } from "./src/config/inScope.js";
import { createRun } from "./src/core/run.js";
import { runInline, enqueueRunJob, startWorker, closeQueue } from "./src/core/queue.js";
import { prisma, disconnectDb } from "./src/db/client.js";
import { logger } from "./src/lib/logger.js";
import { JSON_MODE, VERBOSE } from "./src/lib/mode.js";
import { RunBus, registerBus, unregisterBus } from "./src/core/events.js";
import { createReporter } from "./src/lib/ui.js";
/**
 * Cytadel Sentinel CLI (Phase 1, on-demand).
 *
 *   sentinel setup                       run the idempotent tool installer
 *   sentinel scope validate <file>       validate a scope file
 *   sentinel run <scope-file> [flags]    run the full pipeline on-demand
 *   sentinel status <run-id>             show a run's status + report path
 *   sentinel worker                      run a standalone queue worker
 */
const program = new Command();
program
    .name("sentinel")
    .description("Cytadel Sentinel — authorized, scope-gated web-app pentest pipeline")
    .version("1.0.0");
// ------------------------------------------------------------------ setup ----
program
    .command("setup")
    .description("Run the idempotent tool installer (scripts/setup.sh)")
    .action(async () => {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const script = path.join(here, "scripts", "setup.sh");
    try {
        const { stdout, stderr } = await execRun("bash", [script], {
            allowNonZeroExit: true,
            timeoutMs: 30 * 60 * 1000,
        });
        process.stdout.write(stdout);
        if (stderr)
            process.stderr.write(stderr);
    }
    catch (err) {
        logger.error({ err }, "setup failed");
        process.exitCode = 1;
    }
});
// ------------------------------------------------------------ scope validate -
const scope = program.command("scope").description("Scope operations");
scope
    .command("validate <file>")
    .description("Validate a scope YAML file")
    .action(async (file) => {
    try {
        const loaded = await loadScope(file);
        const s = loaded.scope;
        console.log("✔ scope is valid\n");
        console.log(`  name:              ${s.name}`);
        console.log(`  authorized_by:     ${s.authorized_by}`);
        console.log(`  authorization_ref: ${s.authorization_ref}`);
        console.log(`  scopeHash:         ${loaded.scopeHash}`);
        console.log(`  in_scope domains:  ${s.in_scope.domains.join(", ") || "(none)"}`);
        console.log(`  in_scope urls:     ${s.in_scope.urls.join(", ") || "(none)"}`);
        console.log(`  exclusions:        domains=[${s.exclusions.domains.join(", ")}] paths=[${s.exclusions.paths.join(", ")}]`);
        console.log(`  auth:              ${s.auth.type}${s.auth.session ? ` (env ${s.auth.session})` : ""}`);
        console.log(`  rate_limit_rps:    ${s.rate_limit_rps}`);
        console.log(`  allow_destructive: ${s.allow_destructive}`);
        console.log(`  seed_param_urls:   ${s.seed_param_urls.length ? s.seed_param_urls.join(", ") : "(none)"}`);
        // Show a couple of sample gate decisions so intent is obvious.
        console.log("\n  sample scope-gate decisions:");
        const samples = [
            ...s.in_scope.domains.map((d) => (d.startsWith("*.") ? "sub." + d.slice(2) : d)),
            ...s.exclusions.domains,
        ].slice(0, 6);
        for (const t of samples) {
            const dec = evaluateScope(s, t);
            console.log(`    ${dec.allowed ? "ALLOW" : "DENY "}  ${t}  (${dec.reason})`);
        }
    }
    catch (err) {
        if (err instanceof ScopeValidationError) {
            console.error("✗ scope is INVALID:\n");
            for (const issue of err.issues)
                console.error(`  - ${issue}`);
        }
        else {
            console.error("✗ scope validation error:", err.message);
        }
        process.exitCode = 1;
    }
    finally {
        await disconnectDb().catch(() => undefined);
    }
});
// -------------------------------------------------------------------- run ----
program
    .command("run <scope-file>")
    .description("Run the full pipeline on-demand against a validated scope")
    .option("--allow-destructive", "permit destructive checks (also requires scope allow_destructive: true)", false)
    .option("--detach", "enqueue the job and exit without waiting (needs a running worker)", false)
    .option("--json", "raw JSON log lines instead of the pretty CLI (auto in CI / non-TTY)", false)
    .option("--verbose", "show per-host / debug detail under each stage", false)
    .action(async (scopeFile, opts) => {
    try {
        const { runId, jobData } = await createRun({ scopeFile, allowDestructive: opts.allowDestructive });
        if (opts.detach) {
            await enqueueRunJob(jobData);
            console.log(`run ${runId} queued (detached). Process with: sentinel worker`);
            console.log(`check status with: sentinel status ${runId}`);
            return;
        }
        if (JSON_MODE) {
            // JSON/CI: structured logs already stream to stdout; keep control output minimal.
            console.log(`run ${runId} started`);
            const outcome = await runInline(jobData);
            if (outcome.status === "COMPLETED") {
                console.log(`run ${runId} COMPLETED — report: ${outcome.reportHtmlPath}`);
            }
            else {
                console.error(`run ${runId} FAILED — ${outcome.error}`);
                process.exitCode = 1;
            }
            return;
        }
        // Pretty mode: the reporter owns the terminal via events on a shared bus.
        const bus = new RunBus();
        registerBus(runId, bus);
        const reporter = createReporter(bus, { verbose: VERBOSE });
        try {
            const outcome = await runInline(jobData);
            if (outcome.status === "FAILED")
                process.exitCode = 1;
        }
        finally {
            reporter.detach();
            unregisterBus(runId);
        }
    }
    catch (err) {
        if (err instanceof ScopeValidationError) {
            console.error("✗ scope invalid:");
            for (const issue of err.issues)
                console.error(`  - ${issue}`);
        }
        else {
            console.error("✗ run error:", err.message);
        }
        process.exitCode = 1;
    }
    finally {
        await closeQueue().catch(() => undefined);
        await disconnectDb().catch(() => undefined);
    }
});
// ----------------------------------------------------------------- status ----
program
    .command("status <run-id>")
    .description("Show a run's status, counts, and report path")
    .action(async (runId) => {
    try {
        const run = await prisma.run.findUnique({
            where: { id: runId },
            include: { _count: { select: { assets: true, findings: true } } },
        });
        if (!run) {
            console.error(`✗ no run with id ${runId}`);
            process.exitCode = 1;
            return;
        }
        console.log(`run:        ${run.id}`);
        console.log(`status:     ${run.status}`);
        console.log(`scope:      ${run.scopeName}  (${run.authorizationRef})`);
        console.log(`triggeredBy:${run.triggeredBy}`);
        console.log(`scopeHash:  ${run.scopeHash}`);
        console.log(`assets:     ${run._count.assets}`);
        console.log(`findings:   ${run._count.findings}`);
        console.log(`started:    ${run.startedAt.toISOString()}`);
        console.log(`finished:   ${run.finishedAt ? run.finishedAt.toISOString() : "(running)"}`);
        console.log(`report:     ${run.reportPath ?? "(not yet generated)"}`);
        if (run.error)
            console.log(`error:      ${run.error}`);
    }
    catch (err) {
        console.error("✗ status error:", err.message);
        process.exitCode = 1;
    }
    finally {
        await disconnectDb().catch(() => undefined);
    }
});
// ----------------------------------------------------------------- worker ----
program
    .command("worker")
    .description("Run a standalone BullMQ worker to process queued runs")
    .action(async () => {
    console.log("sentinel worker started — waiting for jobs (Ctrl-C to stop)");
    const worker = startWorker();
    const shutdown = async () => {
        console.log("\nshutting down worker ...");
        await worker.close();
        await disconnectDb().catch(() => undefined);
        process.exit(0);
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
});
program.parseAsync(process.argv).catch((err) => {
    logger.error({ err }, "cli fatal");
    process.exit(1);
});
//# sourceMappingURL=cli.js.map