import { openAsBlob } from "node:fs";
import { logger } from "../../lib/logger.js";

/**
 * DefectDojo API v2 client.
 *
 * DefectDojo owns vulnerability management: storage, cross-run dedupe, and
 * triage. Sentinel uses the native import-scan endpoint (one call per tool
 * artifact, using DefectDojo's built-in parsers) and reads findings back for the
 * branded report.
 *
 * Uses the global fetch (undici) — structured requests only, no shell anywhere.
 */

export interface DefectDojoConfig {
  baseUrl: string;
  apiKey: string;
}

export interface ImportedTest {
  testId: number;
  engagementId: number;
  scanType: string;
}

export interface DojoFinding {
  id: number;
  title: string;
  severity: string;
  numerical_severity?: string;
  description?: string;
  mitigation?: string;
  cve?: string | null;
  cvssv3_score?: number | null;
  epss_score?: number | null;
  active?: boolean;
  verified?: boolean;
  false_p?: boolean;
  duplicate?: boolean;
  component_name?: string | null;
  file_path?: string | null;
  endpoints?: number[];
}

export class DefectDojoClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;

  constructor(config: DefectDojoConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.headers = { Authorization: `Token ${config.apiKey}` };
  }

  /** Build a client from env, throwing a clear error if unconfigured. */
  static fromEnv(): DefectDojoClient {
    const baseUrl = process.env.DEFECTDOJO_URL?.trim();
    const apiKey = process.env.DEFECTDOJO_API_KEY?.trim();
    if (!baseUrl) throw new Error("DEFECTDOJO_URL is not set (see .env.example)");
    if (!apiKey) throw new Error("DEFECTDOJO_API_KEY is not set — get it from the DefectDojo UI (API v2 Key)");
    return new DefectDojoClient({ baseUrl, apiKey });
  }

  private async api<T>(path: string, init: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}/api/v2${path}`;
    const res = await fetch(url, {
      ...init,
      headers: { ...this.headers, ...(init.headers as Record<string, string>) },
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`DefectDojo ${init.method ?? "GET"} ${path} -> ${res.status}: ${body.slice(0, 500)}`);
    }
    return (await res.json()) as T;
  }

  /** Reachability + auth check. */
  async ping(): Promise<boolean> {
    try {
      await this.api("/users/?limit=1");
      return true;
    } catch (err) {
      logger.error({ err }, "DefectDojo ping failed");
      return false;
    }
  }

  private async ensureProductType(): Promise<number> {
    const list = await this.api<{ results: Array<{ id: number }> }>("/product_types/?limit=1");
    if (list.results.length > 0) return list.results[0]!.id;
    const created = await this.api<{ id: number }>("/product_types/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Cytadel Sentinel", description: "Automated pentest pipeline" }),
    });
    return created.id;
  }

  /** Find a product by exact name, or create it. */
  async ensureProduct(name: string, description = "Cytadel Sentinel target"): Promise<number> {
    const found = await this.api<{ results: Array<{ id: number; name: string }> }>(
      `/products/?name=${encodeURIComponent(name)}`,
    );
    const exact = found.results.find((p) => p.name === name);
    if (exact) return exact.id;

    const prodType = await this.ensureProductType();
    const created = await this.api<{ id: number }>("/products/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, description, prod_type: prodType }),
    });
    logger.info({ product: name, id: created.id }, "DefectDojo product created");
    return created.id;
  }

  /** Create an engagement under a product for this run. */
  async createEngagement(params: {
    productId: number;
    name: string;
    startDate: string; // YYYY-MM-DD
    endDate: string; // YYYY-MM-DD
    scopeRef: string;
  }): Promise<number> {
    const created = await this.api<{ id: number }>("/engagements/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: params.name,
        product: params.productId,
        target_start: params.startDate,
        target_end: params.endDate,
        status: "In Progress",
        engagement_type: "CI/CD",
        deduplication_on_engagement: false, // let global cross-run dedupe apply
        description: `Authorization: ${params.scopeRef}`,
      }),
    });
    logger.info({ engagement: params.name, id: created.id }, "DefectDojo engagement created");
    return created.id;
  }

  /**
   * Import one native scan artifact using DefectDojo's built-in parser for that
   * scan_type. Multipart upload via FormData (undici).
   */
  async importScan(params: {
    engagementId: number;
    scanType: string;
    filePath: string;
    active?: boolean;
    verified?: boolean;
  }): Promise<ImportedTest> {
    const form = new FormData();
    form.append("engagement", String(params.engagementId));
    form.append("scan_type", params.scanType);
    form.append("active", String(params.active ?? true));
    form.append("verified", String(params.verified ?? false));
    form.append("close_old_findings", "false");
    const blob = await openAsBlob(params.filePath);
    form.append("file", blob, params.filePath.split(/[/\\]/).pop() ?? "scan");

    const res = await fetch(`${this.baseUrl}/api/v2/import-scan/`, {
      method: "POST",
      headers: this.headers, // do NOT set Content-Type; fetch sets the multipart boundary
      body: form,
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`import-scan ${params.scanType} -> ${res.status}: ${body.slice(0, 500)}`);
    }
    const json = (await res.json()) as { test?: number; test_id?: number };
    const testId = json.test ?? json.test_id ?? 0;
    logger.info({ scanType: params.scanType, testId }, "DefectDojo import-scan ok");
    return { testId, engagementId: params.engagementId, scanType: params.scanType };
  }

  /** Pull all findings for an engagement (paginated). */
  async listFindings(engagementId: number): Promise<DojoFinding[]> {
    const out: DojoFinding[] = [];
    let url: string | null = `/findings/?test__engagement=${engagementId}&limit=100`;
    while (url) {
      const page: { results: DojoFinding[]; next: string | null } = await this.api(url);
      out.push(...page.results);
      // `next` is an absolute URL; strip to the /api/v2-relative path.
      url = page.next ? page.next.replace(/^.*\/api\/v2/, "") : null;
    }
    return out;
  }
}
