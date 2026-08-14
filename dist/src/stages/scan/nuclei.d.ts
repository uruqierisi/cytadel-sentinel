import type { RunContext } from "../../core/context.js";
import type { ScanArtifact } from "./artifacts.js";
/**
 * nuclei — templated web/cve/misconfig/exposure checks over alive in-scope URLs.
 *
 * Targets are fed via stdin (never a shell string). Auth headers are injected so
 * scanning goes past login. Rate limited per scope. Non-destructive template
 * tags only; nuclei's intrusive fuzzing is intentionally NOT enabled here even
 * under --allow-destructive (Phase 1 stays safe by default).
 */
export declare function runNuclei(ctx: RunContext, urls: string[]): Promise<ScanArtifact | null>;
