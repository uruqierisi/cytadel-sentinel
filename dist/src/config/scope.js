import { readFile } from "node:fs/promises";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { ZodError } from "zod";
import { ScopeSchema } from "./schema.js";
import { sha256Of } from "../lib/audit.js";
import { logger } from "../lib/logger.js";
export class ScopeValidationError extends Error {
    issues;
    constructor(message, issues) {
        super(message);
        this.issues = issues;
        this.name = "ScopeValidationError";
    }
}
/** Parse + validate a YAML scope file. Throws ScopeValidationError on bad input. */
export async function loadScope(filePath) {
    const sourcePath = path.resolve(filePath);
    let raw;
    try {
        raw = await readFile(sourcePath, "utf8");
    }
    catch (err) {
        throw new ScopeValidationError(`cannot read scope file: ${sourcePath}`, [
            err.message,
        ]);
    }
    let parsed;
    try {
        parsed = parseYaml(raw);
    }
    catch (err) {
        throw new ScopeValidationError(`scope YAML is not valid`, [err.message]);
    }
    try {
        const scope = ScopeSchema.parse(parsed);
        const scopeHash = sha256Of(scope);
        logger.debug({ sourcePath, scopeHash, name: scope.name }, "scope loaded");
        return { scope, scopeHash, sourcePath };
    }
    catch (err) {
        if (err instanceof ZodError) {
            const issues = err.errors.map((e) => `${e.path.join(".") || "(root)"}: ${e.message}`);
            throw new ScopeValidationError("scope failed validation", issues);
        }
        throw err;
    }
}
//# sourceMappingURL=scope.js.map