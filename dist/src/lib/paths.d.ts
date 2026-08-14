/** Filesystem layout for run artifacts. */
export declare const REPORTS_ROOT: string;
export declare function runDir(runId: string): string;
/** Native tool output files (imported into DefectDojo + parsed by normalize). */
export declare function rawDir(runId: string): string;
/** Downloaded JS assets for retire.js. */
export declare function jsDir(runId: string): string;
export declare function ensureRunDirs(runId: string): Promise<void>;
