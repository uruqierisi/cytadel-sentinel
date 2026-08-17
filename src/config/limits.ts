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
    // dalfox is now batch+budget tuned via LIMITS.dalfox (batchTimeoutMs /
    // budgetMs); this legacy per-run cap is retained only as a fallback default.
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

  /**
   * dalfox speed tuning. dalfox ran ~10 min on a handful of signatures and got
   * SIGTERM-killed mid-write, truncating its JSON array. These flags make it
   * FINISH (so it emits a complete array), and the batch+budget model mirrors
   * sqlmap: run targets in small batches and stop launching new batches once the
   * overall wall-clock budget is spent — completed batches emit complete JSON.
   */
  dalfox: {
    /** dalfox --worker (concurrent workers). */
    worker: intFromEnv("SENTINEL_DALFOX_WORKER", 100),
    /** dalfox --timeout (per HTTP request, seconds). */
    requestTimeoutSec: intFromEnv("SENTINEL_DALFOX_REQ_TIMEOUT_SEC", 10),
    /** Skip dalfox's Basic Another Vulnerability sweep — a big time sink for XSS. */
    skipBav: (process.env.SENTINEL_DALFOX_SKIP_BAV ?? "1") !== "0",
    /**
     * Optional blind-XSS callback URL. When set, `--blind <url>` is added so
     * out-of-band hits are caught; left empty by default so blind testing never
     * adds unbounded requests to a time-boxed run.
     */
    blindCallback: process.env.SENTINEL_DALFOX_BLIND_URL ?? "",
    /** How many deduped signatures per dalfox pipe invocation. */
    batchSize: intFromEnv("SENTINEL_DALFOX_BATCH_SIZE", 10),
    /** Hard exec cap PER batch (ms). */
    batchTimeoutMs: intFromEnv("SENTINEL_DALFOX_BATCH_TIMEOUT_MS", 3 * MIN),
    /** Overall wall-clock budget for the whole dalfox stage (ms). */
    budgetMs: intFromEnv("SENTINEL_DALFOX_BUDGET_MS", 8 * MIN),
  },

  /**
   * sqlmap tuning. sqlmap only runs behind the destructive gate, so these are
   * destructive-run defaults: level/risk 2 with the fast techniques BEU. Full
   * testing (no --smart) at level/risk 2 confirms blind SQLi (e.g. Juice Shop's
   * SQLite search) without T — and time-based (T) heavy queries overloaded the
   * target, so T is left OUT by default but stays available via
   * SENTINEL_SQLMAP_TECHNIQUE=BEUT. Lower threads + higher retries favor
   * injection stability over raw speed.
   */
  sqlmap: {
    level: intFromEnv("SENTINEL_SQLMAP_LEVEL", 2),
    risk: intFromEnv("SENTINEL_SQLMAP_RISK", 2),
    // B=boolean, E=error, U=union. T (time-based) is opt-in via env — its heavy
    // queries can overload the target; S (stacked) stays out (slowest).
    technique: process.env.SENTINEL_SQLMAP_TECHNIQUE ?? "BEU",
    threads: intFromEnv("SENTINEL_SQLMAP_THREADS", 2),
    /** sqlmap --timeout (per HTTP request, seconds). */
    requestTimeoutSec: intFromEnv("SENTINEL_SQLMAP_REQ_TIMEOUT_SEC", 10),
    retries: intFromEnv("SENTINEL_SQLMAP_RETRIES", 2),
    /** Hard exec cap PER target (ms) — was mistakenly 20 min for every URL. */
    targetTimeoutMs: intFromEnv("SENTINEL_SQLMAP_TARGET_TIMEOUT_MS", 90 * 1000),
    /** Overall wall-clock budget for the whole sqlmap stage (ms). */
    budgetMs: intFromEnv("SENTINEL_SQLMAP_BUDGET_MS", 8 * MIN),
  },
} as const;

export type ToolName = keyof typeof LIMITS.toolTimeoutMs;
