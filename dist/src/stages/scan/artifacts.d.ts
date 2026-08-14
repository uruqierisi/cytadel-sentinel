/**
 * A native scanner output file. Each artifact is BOTH imported into DefectDojo
 * (via its native parser) and parsed locally by the normalize stage — one file,
 * two consumers, no re-running the scanner.
 */
export interface ScanArtifact {
    tool: "nuclei" | "nikto" | "testssl" | "retirejs" | "dalfox" | "sqlmap";
    /**
     * DefectDojo `scan_type` string its import-scan endpoint expects. Tools with a
     * native DefectDojo parser use it directly; the active-injection tools
     * (dalfox/sqlmap) emit a "Generic Findings Import" JSON instead.
     */
    dojoScanType: "Nuclei Scan" | "Nikto Scan" | "Testssl Scan" | "Retire.js Scan" | "Generic Findings Import";
    /** Absolute path to the native output file. */
    filePath: string;
    format: "jsonl" | "json" | "csv" | "xml";
    /** Host/URL this artifact covers, or "aggregate" for multi-target files. */
    target: string;
}
