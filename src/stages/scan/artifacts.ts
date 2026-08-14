/**
 * A native scanner output file. Each artifact is BOTH imported into DefectDojo
 * (via its native parser) and parsed locally by the normalize stage — one file,
 * two consumers, no re-running the scanner.
 */
export interface ScanArtifact {
  tool: "nuclei" | "nikto" | "testssl" | "retirejs";
  /** DefectDojo `scan_type` string its import-scan endpoint expects. */
  dojoScanType: "Nuclei Scan" | "Nikto Scan" | "Testssl Scan" | "Retire.js Scan";
  /** Absolute path to the native output file. */
  filePath: string;
  format: "jsonl" | "json" | "csv" | "xml";
  /** Host/URL this artifact covers, or "aggregate" for multi-target files. */
  target: string;
}
