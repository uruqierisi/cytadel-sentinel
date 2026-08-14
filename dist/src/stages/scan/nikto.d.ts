import type { RunContext } from "../../core/context.js";
import type { ScanArtifact } from "./artifacts.js";
/**
 * nikto — server-level web checks, one XML per target. DefectDojo's "Nikto Scan"
 * parser consumes the XML output. Auth cookie/header injected via -id/-H is not
 * uniform across nikto builds, so we pass the cookie via the -H style header
 * where supported and otherwise scan unauthenticated (logged).
 *
 * URL passed as argv only. Non-destructive by default (nikto is read-oriented).
 */
export declare function runNikto(ctx: RunContext, urls: string[]): Promise<ScanArtifact[]>;
