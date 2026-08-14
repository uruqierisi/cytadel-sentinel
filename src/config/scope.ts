import { readFile } from "node:fs/promises";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { ZodError } from "zod";
import { ScopeSchema, type Scope } from "./schema.js";
import { sha256Of } from "../lib/audit.js";
import { logger } from "../lib/logger.js";

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

export class ScopeValidationError extends Error {
  constructor(
    message: string,
    readonly issues: string[],
  ) {
    super(message);
    this.name = "ScopeValidationError";
  }
}

/** Parse + validate a YAML scope file. Throws ScopeValidationError on bad input. */
export async function loadScope(filePath: string): Promise<LoadedScope> {
  const sourcePath = path.resolve(filePath);
  let raw: string;
  try {
    raw = await readFile(sourcePath, "utf8");
  } catch (err) {
    throw new ScopeValidationError(`cannot read scope file: ${sourcePath}`, [
      (err as Error).message,
    ]);
  }

  let parsed: unknown;
  try {
    parsed = parseYaml(raw);
  } catch (err) {
    throw new ScopeValidationError(`scope YAML is not valid`, [(err as Error).message]);
  }

  try {
    const scope = ScopeSchema.parse(parsed);
    const scopeHash = sha256Of(scope);
    logger.debug({ sourcePath, scopeHash, name: scope.name }, "scope loaded");
    return { scope, scopeHash, sourcePath };
  } catch (err) {
    if (err instanceof ZodError) {
      const issues = err.errors.map((e) => `${e.path.join(".") || "(root)"}: ${e.message}`);
      throw new ScopeValidationError("scope failed validation", issues);
    }
    throw err;
  }
}
