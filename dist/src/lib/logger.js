import pino from "pino";
const level = process.env.LOG_LEVEL ?? "info";
const pretty = process.env.LOG_PRETTY === "1";
/**
 * Structured logger. In dev, LOG_PRETTY=1 gives human-readable output via
 * pino-pretty (a devDependency); in CI/prod leave it unset for JSON lines.
 */
export const logger = pino(pretty
    ? {
        level,
        transport: {
            target: "pino-pretty",
            options: { colorize: true, translateTime: "SYS:HH:MM:ss", ignore: "pid,hostname" },
        },
    }
    : { level });
/** Child logger bound to a run id so every line is correlatable. */
export function runLogger(runId) {
    return logger.child({ runId });
}
//# sourceMappingURL=logger.js.map