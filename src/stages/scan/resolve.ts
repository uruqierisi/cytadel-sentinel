import path from "node:path";
import { existsSync } from "node:fs";
import { toolExists } from "../../lib/exec.js";

/**
 * Resolve scanners that setup.sh may install EITHER on PATH (apt/gem) OR as a
 * git checkout under tools/. Returns the executable + any leading args, or null
 * if the tool is unavailable.
 */

export interface ResolvedTool {
  file: string;
  baseArgs: string[];
}

const TOOLS_DIR = path.resolve(process.cwd(), "tools");

export async function resolveNikto(): Promise<ResolvedTool | null> {
  if (await toolExists("nikto", ["-Version"])) return { file: "nikto", baseArgs: [] };
  const pl = path.join(TOOLS_DIR, "nikto", "program", "nikto.pl");
  if (existsSync(pl) && (await toolExists("perl", ["-v"]))) {
    return { file: "perl", baseArgs: [pl] };
  }
  return null;
}

export async function resolveTestssl(): Promise<ResolvedTool | null> {
  if (await toolExists("testssl.sh", ["--version"])) return { file: "testssl.sh", baseArgs: [] };
  const sh = path.join(TOOLS_DIR, "testssl.sh", "testssl.sh");
  if (existsSync(sh)) return { file: sh, baseArgs: [] };
  return null;
}
