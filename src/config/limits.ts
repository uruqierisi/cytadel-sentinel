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
  /** Max (non-JS) endpoints kept per host after gating (one noisy source can't explode a scan). */
  maxEndpointsPerHost: intFromEnv("SENTINEL_MAX_ENDPOINTS_PER_HOST", 300),

  /** JS/static assets are capped in a SEPARATE bucket so retire.js always has input. */
  maxJsAssetsPerHost: intFromEnv("SENTINEL_MAX_JS_ASSETS_PER_HOST", 200),

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
    // dalfox runs as one aggregate pipe over all targets (destructive gate only).
    dalfox: intFromEnv("SENTINEL_DALFOX_TIMEOUT_MS", 10 * MIN),
  },

  /** nuclei per-request tuning — caps requests so a scan can't run unbounded. */
  nuclei: {
    tags: process.env.SENTINEL_NUCLEI_TAGS ?? "cve,misconfiguration,exposure,tech",
    requestTimeoutSec: intFromEnv("SENTINEL_NUCLEI_REQ_TIMEOUT_SEC", 10),
    retries: intFromEnv("SENTINEL_NUCLEI_RETRIES", 1),
    concurrency: intFromEnv("SENTINEL_NUCLEI_CONCURRENCY", 25),
    maxHostError: intFromEnv("SENTINEL_NUCLEI_MAX_HOST_ERROR", 30),
    // Templates match on host/base URLs + unique paths — NOT every crawled param
    // URL. This is the real speed lever: keep the target set small and deduped.
    maxTargets: intFromEnv("SENTINEL_NUCLEI_MAX_TARGETS", 150),
  },

  /**
   * Max DEDUPED param-signatures fed to each active-injection tool. Param URLs
   * are first collapsed by (path + param NAME) — ?id=1 and ?id=2 are the same
   * test — so this cap is on distinct injection signatures, not raw URLs.
   */
  maxInjectionTargets: intFromEnv("SENTINEL_MAX_INJECTION_TARGETS", 25),

  /** sqlmap speed tuning. Defaults trade exhaustiveness for a practical runtime. */
  sqlmap: {
    level: intFromEnv("SENTINEL_SQLMAP_LEVEL", 1),
    risk: intFromEnv("SENTINEL_SQLMAP_RISK", 1),
    // B=boolean, E=error, U=union — the FAST techniques. Drop S (stacked) and
    // T (time-based), which dominate sqlmap's runtime.
    technique: process.env.SENTINEL_SQLMAP_TECHNIQUE ?? "BEU",
    threads: intFromEnv("SENTINEL_SQLMAP_THREADS", 4),
    /** sqlmap --timeout (per HTTP request, seconds). */
    requestTimeoutSec: intFromEnv("SENTINEL_SQLMAP_REQ_TIMEOUT_SEC", 10),
    retries: intFromEnv("SENTINEL_SQLMAP_RETRIES", 1),
    /** Hard exec cap PER target (ms) — was mistakenly 20 min for every URL. */
    targetTimeoutMs: intFromEnv("SENTINEL_SQLMAP_TARGET_TIMEOUT_MS", 90 * 1000),
    /** Overall wall-clock budget for the whole sqlmap stage (ms). */
    budgetMs: intFromEnv("SENTINEL_SQLMAP_BUDGET_MS", 8 * MIN),
  },
} as const;

export type ToolName = keyof typeof LIMITS.toolTimeoutMs;
