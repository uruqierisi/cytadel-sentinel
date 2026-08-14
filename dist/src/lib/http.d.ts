import { request, Client, type Dispatcher } from "undici";
/**
 * undici-based HTTP client for the verification layer (Phase 2) and DefectDojo
 * API calls.
 *
 * NON-NEGOTIABLE RULE: verification replays are built from finding data
 * (untrusted). We NEVER interpolate that data into a shell — we use this client
 * with structured method/url/headers/body. There is no shell anywhere here.
 *
 * SSRF note: verification replays MUST be gated by isInScope() at the call site
 * before this client is invoked. This module does not itself decide scope; it
 * only performs the request it is told to.
 */
export interface HttpRequestOptions {
    method?: Dispatcher.HttpMethod;
    headers?: Record<string, string>;
    /** Raw body (string or Buffer). For JSON, stringify and set content-type yourself. */
    body?: string | Buffer;
    /** Do not follow redirects (default). Verifiers usually want the raw response. */
    maxRedirections?: number;
    timeoutMs?: number;
    /** Cap on response body captured as evidence. Default 512 KiB. */
    maxBodyBytes?: number;
}
export interface HttpResponse {
    status: number;
    headers: Record<string, string | string[] | undefined>;
    body: string;
    truncated: boolean;
    durationMs: number;
    /** The exact request line, retained as reproducible evidence. */
    requestLine: string;
}
/**
 * Perform a single HTTP request and capture the response as evidence.
 * Everything is passed structurally — url, method, headers, body — never a
 * shell string.
 */
export declare function httpRequest(url: string, opts?: HttpRequestOptions): Promise<HttpResponse>;
/**
 * A pooled client for a single origin — used by the DefectDojo integration to
 * reuse connections across many API calls.
 */
export declare function createClient(origin: string): Client;
export { request };
