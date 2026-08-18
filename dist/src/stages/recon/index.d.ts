import { type RunContext } from "../../core/context.js";
import { type HttpxResult } from "./tools.js";
import { type InjectionCandidate } from "../scan/candidates.js";
/**
 * Recon stage.
 *
 * Passive subdomain enumeration -> scope gate -> liveness/fingerprint ->
 * URL/endpoint discovery -> light port context. EVERY discovered asset passes
 * through the scope gate before it is kept or touched. Results are persisted as
 * Asset rows and the alive web targets are handed to the scan stage.
 */
export interface ReconResult {
    /** Alive web targets (in-scope) with fingerprints — input to the scan stage. */
    webTargets: HttpxResult[];
    /** In-scope JS asset URLs — fed to retire.js. */
    jsUrls: string[];
    /** In-scope URLs carrying query params — fed to active-injection tools (gated). */
    paramUrls: string[];
    /** In-scope non-JS endpoints (capped) — reduced to base/unique paths for nuclei. */
    endpoints: string[];
    /**
     * Method-aware injection candidates from ALL discovery sources (discovery /
     * JS analysis / OpenAPI / GraphQL), each already scope-gated. Fed to the
     * active-injection tools alongside scope seeds.
     */
    injectionCandidates: InjectionCandidate[];
    /** Coverage notes from WP2 discovery (JS/OpenAPI/GraphQL — why a source was empty). */
    discoveryNotes: string[];
    /** Count of every asset persisted this run. */
    assetCount: number;
}
export declare function runRecon(ctx: RunContext): Promise<ReconResult>;
