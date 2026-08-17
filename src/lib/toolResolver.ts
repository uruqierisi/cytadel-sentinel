import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import type { Logger } from "pino";
import { run } from "./exec.js";

/**
 * Tool resolver.
 *
 * WHY THIS EXISTS: the pipeline used to spawn recon binaries by BARE NAME
 * ("httpx", "subfinder", …), which lets PATH order decide which binary wins. On
 * a box with a Python `httpx` in ~/.local/bin and the ProjectDiscovery `httpx`
 * in ~/go/bin, whichever comes first on PATH is used. When Python's wins, it
 * doesn't understand `-json`/`-silent` and recon silently returns 0 web
 * targets.
 *
 * This module removes PATH-order ambiguity entirely:
 *   - every external tool is resolved to an ABSOLUTE PATH once, at startup;
 *   - ~/go/bin is always preferred for the Go/ProjectDiscovery tools;
 *   - httpx is VERIFIED to be the ProjectDiscovery build (its `-version` banner),
 *     and if the first candidate is the wrong build we keep searching the other
 *     known locations for the correct one;
 *   - if a tool is PRESENT but is the WRONG build and no correct build can be
 *     found, resolution FAILS LOUDLY (throws) instead of letting the run drift
 *     to a silent 0-result outcome.
 *
 * A tool that is simply ABSENT (not installed anywhere) is not an error here —
 * the stage wrappers degrade gracefully and log a skip, exactly as before. The
 * loud failure is reserved for the "wrong build shadowing the right one" case.
 */

/** How a spec decides which on-disk candidate is the correct binary. */
export interface ToolSpec {
  /** Logical id used by callers (e.g. "httpx"). Also the on-disk basename. */
  name: string;
  /**
   * Args used to probe the tool's version/identity. Omit for "existence-only"
   * tools that have no safe, fast version flag — the first executable candidate
   * (go/bin preferred) is then accepted without being run.
   */
  versionArgs?: string[];
  /**
   * Given the combined stdout+stderr of the version probe, return true iff this
   * candidate is the CORRECT build. Omit for a lenient check (any candidate that
   * runs is accepted). Only meaningful when `versionArgs` is set.
   */
  verify?: (probeOutput: string) => boolean;
  /** Human-readable description of what a correct build looks like (for errors). */
  expects?: string;
}

export interface ResolvedTool {
  name: string;
  /** Absolute path to the chosen executable. */
  path: string;
  /** First line of the version probe (or "present" for existence-only tools). */
  version: string;
}

/** A candidate that ran but failed verification — used to build a loud error. */
interface RejectedCandidate {
  path: string;
  output: string;
}

type ResolveOutcome =
  | { status: "ok"; resolved: ResolvedTool }
  | { status: "absent" }
  | { status: "mismatch"; rejected: RejectedCandidate[] };

/**
 * httpx identity check. ProjectDiscovery httpx `-version` prints a banner such
 * as `[INF] Current httpx version v1.6.9 (latest)`. The Python `httpx` CLI does
 * not understand `-version` and, when it prints anything, never carries a PD
 * version banner. We accept only output that looks like the PD build.
 */
export function isProjectDiscoveryHttpx(probeOutput: string): boolean {
  const s = probeOutput.toLowerCase();
  if (!s.trim()) return false;
  // Positive PD markers.
  return (
    /projectdiscovery/.test(s) ||
    /current httpx version/.test(s) ||
    /httpx\s+version/.test(s) ||
    /\bv\d+\.\d+\.\d+/.test(s) // PD prints a leading-'v' semver; Python prints bare "0.27.0"
  );
}

/** The tools we resolve to absolute paths up front. */
export const TOOL_SPECS: readonly ToolSpec[] = [
  // ProjectDiscovery tools — always preferred from ~/go/bin.
  {
    name: "subfinder",
    versionArgs: ["-version"],
    expects: "ProjectDiscovery subfinder (go install)",
  },
  {
    name: "httpx",
    versionArgs: ["-version"],
    verify: isProjectDiscoveryHttpx,
    expects: "ProjectDiscovery httpx (NOT the Python 'httpx' package)",
  },
  {
    name: "naabu",
    versionArgs: ["-version"],
    expects: "ProjectDiscovery naabu (go install)",
  },
  {
    name: "katana",
    versionArgs: ["-version"],
    expects: "ProjectDiscovery katana (go install)",
  },
  {
    name: "nuclei",
    versionArgs: ["-version"],
    expects: "ProjectDiscovery nuclei (go install)",
  },
  // Other Go recon tools — resolved to absolute paths (go/bin preferred). These
  // have no fast, side-effect-free version flag, so we accept the first
  // executable candidate without running it.
  { name: "gau", expects: "gau (go install)" },
  { name: "waybackurls", expects: "waybackurls (go install)" },
];

const PROBE_TIMEOUT_MS = 10_000;

/** Directories to search, in priority order. ~/go/bin first for Go tools. */
function searchDirs(): string[] {
  const home = os.homedir();
  const goBin = process.env.GOBIN || path.join(home, "go", "bin");
  const pathDirs = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  const common = ["/usr/local/bin", "/usr/bin", "/bin", path.join(home, ".local", "bin")];
  // go/bin first (wins over a shadowing PATH entry), then the real PATH, then
  // common fallbacks. Dedupe while preserving first-seen order.
  const seen = new Set<string>();
  const out: string[] = [];
  for (const d of [goBin, ...pathDirs, ...common]) {
    const norm = path.normalize(d);
    if (!seen.has(norm)) {
      seen.add(norm);
      out.push(norm);
    }
  }
  return out;
}

/** Candidate basenames for a tool (add .exe on Windows). */
function basenames(name: string): string[] {
  return process.platform === "win32" ? [`${name}.exe`, name] : [name];
}

function isExecutableFile(p: string): boolean {
  try {
    const st = fs.statSync(p);
    if (!st.isFile()) return false;
    if (process.platform === "win32") return true;
    fs.accessSync(p, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Absolute executable paths for a tool, go/bin first, deduped. */
function candidatePaths(name: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const dir of searchDirs()) {
    for (const base of basenames(name)) {
      const p = path.join(dir, base);
      if (!seen.has(p) && isExecutableFile(p)) {
        seen.add(p);
        out.push(p);
      }
    }
  }
  return out;
}

function firstLine(s: string): string {
  return s.split("\n")[0]?.trim() || "";
}

/** Run a version probe. Returns null if the binary could not be executed. */
async function probe(absPath: string, versionArgs: string[]): Promise<string | null> {
  try {
    const { stdout, stderr } = await run(absPath, versionArgs, {
      timeoutMs: PROBE_TIMEOUT_MS,
      allowNonZeroExit: true,
    });
    return `${stdout}\n${stderr}`;
  } catch {
    // ENOENT / spawn failure — treat as "did not run".
    return null;
  }
}

async function resolveOne(spec: ToolSpec): Promise<ResolveOutcome> {
  const candidates = candidatePaths(spec.name);
  if (candidates.length === 0) return { status: "absent" };

  // Existence-only tool: first executable candidate (go/bin preferred) wins.
  if (!spec.versionArgs) {
    return {
      status: "ok",
      resolved: { name: spec.name, path: candidates[0]!, version: "present" },
    };
  }

  const rejected: RejectedCandidate[] = [];
  for (const candidate of candidates) {
    const output = await probe(candidate, spec.versionArgs);
    if (output === null) continue; // could not run this one — try the next
    const accepted = spec.verify ? spec.verify(output) : true;
    if (accepted) {
      return {
        status: "ok",
        resolved: { name: spec.name, path: candidate, version: firstLine(output) || "unknown" },
      };
    }
    rejected.push({ path: candidate, output: firstLine(output) });
  }

  // Candidates existed. If at least one RAN but none verified, that is the
  // shadowing/wrong-build case → loud failure. If none even ran, it's absent.
  return rejected.length > 0 ? { status: "mismatch", rejected } : { status: "absent" };
}

/** Raised when a tool is present on the box but is the wrong build. */
export class ToolResolutionError extends Error {
  constructor(public readonly problems: string[]) {
    super(
      `tool resolution failed — refusing to run with a wrong/shadowed binary:\n` +
        problems.map((p) => `  - ${p}`).join("\n"),
    );
    this.name = "ToolResolutionError";
  }
}

/**
 * Registry of resolved tools. Construct once per run; call `resolveAll` at
 * startup (it throws on a wrong-build mismatch), then `pathFor` at every call
 * site instead of spawning by bare name.
 */
export class ToolRegistry {
  private readonly resolved = new Map<string, ResolvedTool>();
  private readonly absent = new Set<string>();
  private done = false;

  /**
   * Resolve every spec to an absolute path. Throws {@link ToolResolutionError}
   * if any tool is present but is the wrong build (e.g. Python httpx shadowing
   * the ProjectDiscovery one) — never degrades silently.
   */
  async resolveAll(log?: Logger, specs: readonly ToolSpec[] = TOOL_SPECS): Promise<void> {
    const problems: string[] = [];
    for (const spec of specs) {
      const outcome = await resolveOne(spec);
      if (outcome.status === "ok") {
        this.resolved.set(spec.name, outcome.resolved);
        log?.info(
          { tool: spec.name, path: outcome.resolved.path, version: outcome.resolved.version },
          "tool resolved",
        );
      } else if (outcome.status === "absent") {
        this.absent.add(spec.name);
        log?.warn({ tool: spec.name }, "tool not found — stage will skip it (run scripts/setup.sh in WSL2/Linux)");
      } else {
        const found = outcome.rejected
          .map((r) => `${r.path} (probe: ${r.output || "<no output>"})`)
          .join("; ");
        problems.push(
          `${spec.name}: found the wrong build — ${found}. Expected ${spec.expects ?? "the correct build"}. ` +
            `Install it and ensure ~/go/bin precedes any shadowing directory on PATH.`,
        );
        log?.error({ tool: spec.name, rejected: outcome.rejected }, "tool resolved to the WRONG build");
      }
    }
    this.done = true;
    if (problems.length > 0) throw new ToolResolutionError(problems);
  }

  /** Absolute path for a resolved tool, or null if the tool is absent. */
  pathFor(name: string): string | null {
    return this.resolved.get(name)?.path ?? null;
  }

  info(name: string): ResolvedTool | undefined {
    return this.resolved.get(name);
  }

  isResolved(): boolean {
    return this.done;
  }
}
