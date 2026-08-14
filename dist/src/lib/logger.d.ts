import pino from "pino";
/**
 * Structured logger. In dev, LOG_PRETTY=1 gives human-readable output via
 * pino-pretty (a devDependency); in CI/prod leave it unset for JSON lines.
 */
export declare const logger: pino.Logger<never, boolean>;
/** Child logger bound to a run id so every line is correlatable. */
export declare function runLogger(runId: string): pino.Logger<never, boolean>;
