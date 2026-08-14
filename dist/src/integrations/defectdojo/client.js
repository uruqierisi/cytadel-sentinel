import { openAsBlob } from "node:fs";
import { logger } from "../../lib/logger.js";
export class DefectDojoClient {
    baseUrl;
    headers;
    constructor(config) {
        this.baseUrl = config.baseUrl.replace(/\/+$/, "");
        this.headers = { Authorization: `Token ${config.apiKey}` };
    }
    /** Build a client from env, throwing a clear error if unconfigured. */
    static fromEnv() {
        const baseUrl = process.env.DEFECTDOJO_URL?.trim();
        const apiKey = process.env.DEFECTDOJO_API_KEY?.trim();
        if (!baseUrl)
            throw new Error("DEFECTDOJO_URL is not set (see .env.example)");
        if (!apiKey)
            throw new Error("DEFECTDOJO_API_KEY is not set — get it from the DefectDojo UI (API v2 Key)");
        return new DefectDojoClient({ baseUrl, apiKey });
    }
    async api(path, init = {}) {
        const url = `${this.baseUrl}/api/v2${path}`;
        const res = await fetch(url, {
            ...init,
            headers: { ...this.headers, ...init.headers },
        });
        if (!res.ok) {
            const body = await res.text().catch(() => "");
            throw new Error(`DefectDojo ${init.method ?? "GET"} ${path} -> ${res.status}: ${body.slice(0, 500)}`);
        }
        return (await res.json());
    }
    /** Reachability + auth check. */
    async ping() {
        try {
            await this.api("/users/?limit=1");
            return true;
        }
        catch (err) {
            logger.error({ err }, "DefectDojo ping failed");
            return false;
        }
    }
    async ensureProductType() {
        const list = await this.api("/product_types/?limit=1");
        if (list.results.length > 0)
            return list.results[0].id;
        const created = await this.api("/product_types/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: "Cytadel Sentinel", description: "Automated pentest pipeline" }),
        });
        return created.id;
    }
    /** Find a product by exact name, or create it. */
    async ensureProduct(name, description = "Cytadel Sentinel target") {
        const found = await this.api(`/products/?name=${encodeURIComponent(name)}`);
        const exact = found.results.find((p) => p.name === name);
        if (exact)
            return exact.id;
        const prodType = await this.ensureProductType();
        const created = await this.api("/products/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, description, prod_type: prodType }),
        });
        logger.info({ product: name, id: created.id }, "DefectDojo product created");
        return created.id;
    }
    /** Create an engagement under a product for this run. */
    async createEngagement(params) {
        const created = await this.api("/engagements/", {
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
    async importScan(params) {
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
        const json = (await res.json());
        const testId = json.test ?? json.test_id ?? 0;
        logger.info({ scanType: params.scanType, testId }, "DefectDojo import-scan ok");
        return { testId, engagementId: params.engagementId, scanType: params.scanType };
    }
    /** Pull all findings for an engagement (paginated). */
    async listFindings(engagementId) {
        const out = [];
        let url = `/findings/?test__engagement=${engagementId}&limit=100`;
        while (url) {
            const page = await this.api(url);
            out.push(...page.results);
            // `next` is an absolute URL; strip to the /api/v2-relative path.
            url = page.next ? page.next.replace(/^.*\/api\/v2/, "") : null;
        }
        return out;
    }
}
//# sourceMappingURL=client.js.map