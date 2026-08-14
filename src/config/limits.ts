/**
 * Recon/scan tuning knobs. Configurable via env with safe defaults.
 *
 * These live OUTSIDE the scope YAML on purpose: scope content feeds the scope
 * hash (an audit value), and these operational limits must not perturb it.
 * Changing a limit never changes scope-gate semantics or any audit field.
 */

function intFromEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

const MIN = 60 * 1000;

export const LIMITS = {
  /** Max endpoints kept per host after gating (one noisy source can't explode a scan). */
  maxEndpointsPerHost: intFromEnv("SENTINEL_MAX_ENDPOINTS_PER_HOST", 300),

  /** How often a long-running tool emits an elapsed-time progress heartbeat. */
  progressIntervalMs: intFromEnv("SENTINEL_PROGRESS_INTERVAL_MS", 60 * 1000),

  /** Per-tool hard timeouts (ms). */
  toolTimeoutMs: {
    subfinder: intFromEnv("SENTINEL_SUBFINDER_TIMEOUT_MS", 5 * MIN),
    httpx: intFromEnv("SENTINEL_HTTPX_TIMEOUT_MS", 10 * MIN),
    katana: intFromEnv("SENTINEL_KATANA_TIMEOUT_MS", 5 * MIN),
    gau: intFromEnv("SENTINEL_GAU_TIMEOUT_MS", 3 * MIN),
    waybackurls: intFromEnv("SENTINEL_WAYBACKURLS_TIMEOUT_MS", 3 * MIN),
    naabu: intFromEnv("SENTINEL_NAABU_TIMEOUT_MS", 5 * MIN),
    nuclei: intFromEnv("SENTINEL_NUCLEI_TIMEOUT_MS", 15 * MIN),
    nikto: intFromEnv("SENTINEL_NIKTO_TIMEOUT_MS", 8 * MIN),
    testssl: intFromEnv("SENTINEL_TESTSSL_TIMEOUT_MS", 10 * MIN),
    retire: intFromEnv("SENTINEL_RETIRE_TIMEOUT_MS", 5 * MIN),
    // Active injection (destructive gate only).
    dalfox: intFromEnv("SENTINEL_DALFOX_TIMEOUT_MS", 15 * MIN),
    sqlmap: intFromEnv("SENTINEL_SQLMAP_TIMEOUT_MS", 20 * MIN),
  },

  /** nuclei per-request tuning — caps requests so a scan can't run unbounded. */
  nuclei: {
    tags: process.env.SENTINEL_NUCLEI_TAGS ?? "cve,misconfiguration,exposure,tech",
    requestTimeoutSec: intFromEnv("SENTINEL_NUCLEI_REQ_TIMEOUT_SEC", 10),
    retries: intFromEnv("SENTINEL_NUCLEI_RETRIES", 1),
    concurrency: intFromEnv("SENTINEL_NUCLEI_CONCURRENCY", 25),
    maxHostError: intFromEnv("SENTINEL_NUCLEI_MAX_HOST_ERROR", 30),
  },

  /** Max param-URLs fed to each active-injection tool (kept bounded even when gated open). */
  maxInjectionTargets: intFromEnv("SENTINEL_MAX_INJECTION_TARGETS", 50),
} as const;

export type ToolName = keyof typeof LIMITS.toolTimeoutMs;
