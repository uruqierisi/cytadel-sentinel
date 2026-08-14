import { request, Client } from "undici";
import { logger } from "./logger.js";
const DEFAULT_TIMEOUT_MS = 20_000;
const DEFAULT_MAX_BODY = 512 * 1024;
/**
 * Perform a single HTTP request and capture the response as evidence.
 * Everything is passed structurally — url, method, headers, body — never a
 * shell string.
 */
export async function httpRequest(url, opts = {}) {
    const method = opts.method ?? "GET";
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY;
    const startedAt = Date.now();
    // Validate the URL up front so a malformed finding-derived URL fails loudly
    // rather than being coerced into something unexpected.
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        throw new Error(`httpRequest: refusing non-http(s) protocol "${parsed.protocol}"`);
    }
    const res = await request(url, {
        method,
        headers: opts.headers,
        body: opts.body,
        maxRedirections: opts.maxRedirections ?? 0,
        headersTimeout: timeoutMs,
        bodyTimeout: timeoutMs,
    });
    const chunks = [];
    let total = 0;
    let truncated = false;
    for await (const chunk of res.body) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        if (total + buf.length > maxBodyBytes) {
            chunks.push(buf.subarray(0, maxBodyBytes - total));
            truncated = true;
            break;
        }
        chunks.push(buf);
        total += buf.length;
    }
    // Drain remainder if we broke early, so the socket can be reused/closed.
    if (truncated) {
        res.body.destroy();
    }
    const durationMs = Date.now() - startedAt;
    const response = {
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString("utf8"),
        truncated,
        durationMs,
        requestLine: `${method} ${url}`,
    };
    logger.debug({ method, url, status: response.status, durationMs, truncated }, "http request finished");
    return response;
}
/**
 * A pooled client for a single origin — used by the DefectDojo integration to
 * reuse connections across many API calls.
 */
export function createClient(origin) {
    return new Client(origin);
}
export { request };
//# sourceMappingURL=http.js.map