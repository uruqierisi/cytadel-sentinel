/**
 * DefectDojo API v2 client.
 *
 * DefectDojo owns vulnerability management: storage, cross-run dedupe, and
 * triage. Sentinel uses the native import-scan endpoint (one call per tool
 * artifact, using DefectDojo's built-in parsers) and reads findings back for the
 * branded report.
 *
 * Uses the global fetch (undici) — structured requests only, no shell anywhere.
 */
export interface DefectDojoConfig {
    baseUrl: string;
    apiKey: string;
}
export interface ImportedTest {
    testId: number;
    engagementId: number;
    scanType: string;
}
export interface DojoFinding {
    id: number;
    title: string;
    severity: string;
    numerical_severity?: string;
    description?: string;
    mitigation?: string;
    cve?: string | null;
    cvssv3_score?: number | null;
    epss_score?: number | null;
    active?: boolean;
    verified?: boolean;
    false_p?: boolean;
    duplicate?: boolean;
    component_name?: string | null;
    file_path?: string | null;
    endpoints?: number[];
}
export declare class DefectDojoClient {
    private readonly baseUrl;
    private readonly headers;
    constructor(config: DefectDojoConfig);
    /** Build a client from env, throwing a clear error if unconfigured. */
    static fromEnv(): DefectDojoClient;
    private api;
    /** Reachability + auth check. */
    ping(): Promise<boolean>;
    private ensureProductType;
    /** Find a product by exact name, or create it. */
    ensureProduct(name: string, description?: string): Promise<number>;
    /** Create an engagement under a product for this run. */
    createEngagement(params: {
        productId: number;
        name: string;
        startDate: string;
        endDate: string;
        scopeRef: string;
    }): Promise<number>;
    /**
     * Import one native scan artifact using DefectDojo's built-in parser for that
     * scan_type. Multipart upload via FormData (undici).
     */
    importScan(params: {
        engagementId: number;
        scanType: string;
        filePath: string;
        active?: boolean;
        verified?: boolean;
    }): Promise<ImportedTest>;
    /** Pull all findings for an engagement (paginated). */
    listFindings(engagementId: number): Promise<DojoFinding[]>;
}
