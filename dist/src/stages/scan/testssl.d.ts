import type { RunContext } from "../../core/context.js";
import type { ScanArtifact } from "./artifacts.js";
/**
 * testssl.sh — TLS/SSL configuration issues, one CSV per host. DefectDojo's
 * "Testssl Scan" parser consumes the CSV (--csvfile) output.
 *
 * Non-destructive (read-only TLS negotiation). host:port passed as argv only.
 */
export declare function runTestssl(ctx: RunContext, hostports: string[]): Promise<ScanArtifact[]>;
