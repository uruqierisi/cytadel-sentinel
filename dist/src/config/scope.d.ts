import { type Scope } from "./schema.js";
/**
 * A loaded, validated scope plus its content hash and the matcher gate.
 */
export interface LoadedScope {
    scope: Scope;
    /** sha256 over the canonicalized scope object — stable per logical scope. */
    scopeHash: string;
    /** Absolute path the scope was loaded from. */
    sourcePath: string;
}
export declare class ScopeValidationError extends Error {
    readonly issues: string[];
    constructor(message: string, issues: string[]);
}
/** Parse + validate a YAML scope file. Throws ScopeValidationError on bad input. */
export declare function loadScope(filePath: string): Promise<LoadedScope>;
