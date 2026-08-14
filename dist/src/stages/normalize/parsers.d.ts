import { type UnifiedFinding } from "./types.js";
/**
 * Per-tool parsers: native output -> UnifiedFinding[]. These feed the local
 * lightweight Finding table + dedupe. DefectDojo remains the authoritative
 * parser for its own storage; this is a parallel, minimal read.
 */
export declare function parseNuclei(content: string): UnifiedFinding[];
export declare function parseRetire(content: string): UnifiedFinding[];
/**
 * Parse the DefectDojo "Generic Findings Import" JSON that the active-injection
 * tools emit (see stages/scan/generic.ts). The same file feeds both DefectDojo
 * and this parser, so the shape is the shared contract.
 */
export declare function parseGeneric(content: string, fallbackTool: string): UnifiedFinding[];
export declare function parseTestssl(content: string): UnifiedFinding[];
export declare function parseNikto(content: string): UnifiedFinding[];
/** Minimal CSV parser handling quoted fields and embedded commas/quotes. */
export declare function parseCsv(content: string): string[][];
