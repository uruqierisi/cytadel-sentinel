/**
 * Coverage tracking (WP4).
 *
 * A client report must state what was TESTED, not only what was found — that is
 * what gives a client confidence nothing was silently skipped. This model is a
 * mutable accumulator on the RunContext: recon fills discovery/caps, scan fills
 * what was actually fuzzed, the orchestrator fills auth + tool versions, and the
 * report renders it. Every cap/skip that reduces coverage lands here (not just
 * in logs), so a limitation is always visible.
 */

export type AuthCoverageState = "authenticated" | "anonymous" | "degraded";

/** A cap that dropped work — recorded with its value and how much was dropped. */
export interface CoverageCap {
  /** Human name, e.g. "endpoint cap". */
  name: string;
  cap: number;
  dropped: number;
  /** Optional context, e.g. "3 host(s)". */
  detail?: string;
}

export interface ToolVersion {
  name: string;
  version: string;
}

export interface InjectionCoverage {
  /** GET query candidates fuzzed. */
  get: number;
  /** POST/PUT body candidates fuzzed. */
  post: number;
  /** True if active injection ran at all this run. */
  ran: boolean;
  /** Why injection was skipped (destructive gate closed), if it was. */
  skippedReason?: string;
}

export interface RunCoverage {
  hosts: { discovered: number; tested: number };
  endpoints: { discovered: number; tested: number };
  params: { discovered: number; tested: number };
  /** WP2 per-source candidate counts (discovery/js/openapi/graphql/seed). */
  candidatesBySource: Record<string, number>;
  injection: InjectionCoverage;
  auth: { state: AuthCoverageState; mode: string };
  tools: ToolVersion[];
  caps: CoverageCap[];
  /** Discovery notes from WP2 (why a source was empty, JS asset count, …). */
  notes: string[];
}

export function newCoverage(): RunCoverage {
  return {
    hosts: { discovered: 0, tested: 0 },
    endpoints: { discovered: 0, tested: 0 },
    params: { discovered: 0, tested: 0 },
    candidatesBySource: {},
    injection: { get: 0, post: 0, ran: false },
    auth: { state: "anonymous", mode: "none" },
    tools: [],
    caps: [],
    notes: [],
  };
}

/**
 * Compute the human-readable "Coverage limitations" list — every cap, skip, and
 * reduced-coverage reason for this run. This is what the client reads to know
 * what was NOT fully tested.
 */
export function coverageLimitations(cov: RunCoverage): string[] {
  const out: string[] = [];

  // Auth.
  if (cov.auth.state === "degraded") {
    out.push(
      "Authentication DEGRADED mid-run — the session was lost and could not be recovered; " +
        "content behind login may be under-tested (remaining requests were unauthenticated).",
    );
  } else if (cov.auth.state === "anonymous" && cov.auth.mode !== "none") {
    out.push("Scanned ANONYMOUSLY — authentication was configured but no session was established; content behind login was not tested.");
  }

  // Caps.
  for (const cap of cov.caps) {
    out.push(
      `${cap.name} hit (limit ${cap.cap}${cap.detail ? `, ${cap.detail}` : ""}): ${cap.dropped} item(s) dropped and NOT tested.`,
    );
  }

  // Injection.
  if (cov.injection.skippedReason) {
    out.push(`Active injection testing (SQLi/XSS) was NOT performed — ${cov.injection.skippedReason}.`);
  } else if (cov.injection.ran && cov.injection.post === 0) {
    out.push("POST/PUT request bodies were not tested (no body candidates discovered — provide an OpenAPI spec, GraphQL, or seed_param_urls).");
  }

  // WP2 discovery notes (dedup, they explain empty sources).
  for (const note of cov.notes) {
    if (!out.includes(note)) out.push(note);
  }

  return out;
}
