import { readdir, readFile, writeFile, stat } from "node:fs/promises";
import path from "node:path";
import type { ResolvedAuth } from "../config/auth.js";

/**
 * Secret scrubbing for raw artifacts.
 *
 * The scanners need the REAL auth material at runtime, but several of them echo
 * their full command line into on-disk output — sqlmap writes
 * `-H "Authorization: Bearer <JWT>"` / `--cookie <value>` into
 * <output-dir>/<host>/target.txt, and the token can also land in its `log` and
 * `session.sqlite`. That plaintext token decodes to the client's identity, so it
 * must never remain in a raw artifact (WP1 invariant).
 *
 * This module masks every occurrence of the session secret(s) across a directory
 * tree AFTER the tools have run. Replacement is a same-length `*` mask so binary
 * containers (session.sqlite) keep their byte offsets/validity.
 */

/** Secrets shorter than this are not tree-scrubbed (too generic to mask safely). */
const MIN_SECRET_LEN = 8;

/**
 * Distinct secret strings to scrub, derived from the live auth material:
 * the cookie string and its long values, every auth header value, and the bare
 * token behind a Bearer/Basic/Token scheme. Longest first so a superset is
 * masked before its substring.
 */
export function authSecretValues(auth: ResolvedAuth): string[] {
  const set = new Set<string>();
  if (auth.cookie) {
    set.add(auth.cookie);
    for (const pair of auth.cookie.split(/;\s*/)) {
      const eq = pair.indexOf("=");
      if (eq > 0) set.add(pair.slice(eq + 1));
    }
  }
  for (const value of Object.values(auth.headerMap)) {
    if (!value) continue;
    set.add(value);
    const m = value.match(/^\s*(?:Bearer|Basic|Token)\s+(.+)$/i);
    if (m) set.add(m[1]!);
  }
  return [...set].filter((s) => s.length >= MIN_SECRET_LEN).sort((a, b) => b.length - a.length);
}

/** Same-length mask so binary structure (and text alignment) is preserved. */
function maskFor(secret: string): Buffer {
  return Buffer.alloc(Buffer.byteLength(secret, "utf8"), 0x2a); // '*'
}

/** Replace every secret occurrence in a buffer in place (same length). Returns count. */
export function scrubBuffer(buf: Buffer, secrets: string[]): number {
  let count = 0;
  for (const secret of secrets) {
    const needle = Buffer.from(secret, "utf8");
    if (needle.length === 0) continue;
    const mask = maskFor(secret);
    let idx = buf.indexOf(needle);
    while (idx !== -1) {
      mask.copy(buf, idx);
      count++;
      idx = buf.indexOf(needle, idx + needle.length);
    }
  }
  return count;
}

/** Scrub secrets from a single string. */
export function scrubString(text: string, secrets: string[]): string {
  const buf = Buffer.from(text, "utf8");
  scrubBuffer(buf, secrets);
  return buf.toString("utf8");
}

export interface ScrubResult {
  scanned: number;
  filesModified: number;
  occurrences: number;
}

/** Recursively scrub every file under `dir`. No-op if `secrets` is empty. */
export async function scrubTree(dir: string, secrets: string[]): Promise<ScrubResult> {
  const result: ScrubResult = { scanned: 0, filesModified: 0, occurrences: 0 };
  if (secrets.length === 0) return result;
  await walk(dir, async (file) => {
    result.scanned++;
    const buf = await readFile(file);
    const count = scrubBuffer(buf, secrets);
    if (count > 0) {
      await writeFile(file, buf);
      result.filesModified++;
      result.occurrences += count;
    }
  });
  return result;
}

/**
 * Verification: return the list of files under `dir` that STILL contain any
 * secret. Empty array == clean. Used by the runtime check and by tests to fail
 * loudly on a leak.
 */
export async function findSecretLeaks(dir: string, secrets: string[]): Promise<string[]> {
  const leaks: string[] = [];
  if (secrets.length === 0) return leaks;
  const needles = secrets.map((s) => Buffer.from(s, "utf8"));
  await walk(dir, async (file) => {
    const buf = await readFile(file);
    if (needles.some((n) => buf.indexOf(n) !== -1)) leaks.push(file);
  });
  return leaks;
}

/** Depth-first walk over regular files under `dir` (missing dir = no-op). */
async function walk(dir: string, visit: (file: string) => Promise<void>): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      await walk(full, visit);
    } else if (e.isFile()) {
      try {
        const s = await stat(full);
        if (s.isFile()) await visit(full);
      } catch {
        /* file vanished between readdir and stat — skip */
      }
    }
  }
}
