/**
 * Presentation mode — decided ONCE at process start from argv + env + TTY.
 *
 * This module has no imports beyond Node globals so it is safe to evaluate
 * first (logger.ts depends on it to pick its sink). It only reads process
 * state that is available immediately, so importing it before flags are parsed
 * by commander is fine.
 *
 * Rules (from the spec):
 *   - default: pretty CLI (human reporter owns the terminal).
 *   - --json OR CI=true OR non-TTY stdout: raw JSON lines (piping/CI).
 *   - --verbose: reporter shows per-host / debug detail under each stage.
 *   - SENTINEL_UI=pretty|json: explicit override (mainly for tests/demos).
 */

function computeMode(): { json: boolean; verbose: boolean } {
  const argv = process.argv;
  const override = process.env.SENTINEL_UI?.toLowerCase();

  const verbose = argv.includes("--verbose");

  if (override === "pretty") return { json: false, verbose };
  if (override === "json") return { json: true, verbose };

  const jsonFlag = argv.includes("--json");
  const ci = process.env.CI === "true" || process.env.CI === "1";
  const nonTty = !process.stdout.isTTY;

  return { json: jsonFlag || ci || nonTty, verbose };
}

const mode = computeMode();

/** True when the terminal should receive raw structured JSON (CI / piping). */
export const JSON_MODE = mode.json;

/** True when the pretty human reporter owns the terminal. */
export const PRETTY_MODE = !mode.json;

/** True when the reporter should show per-host / debug detail under each stage. */
export const VERBOSE = mode.verbose;
