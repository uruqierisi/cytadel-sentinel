import pino from "pino";
export declare const logger: pino.Logger<never, boolean>;
/** Child logger bound to a run id so every line is correlatable. */
export declare function runLogger(runId: string): pino.Logger<never, boolean>;
