import type { RunContext } from "../../core/context.js";
/** subfinder: passive subdomain enumeration for one apex domain. */
export declare function subfinder(ctx: RunContext, domain: string): Promise<string[]>;
export interface HttpxResult {
    host: string;
    url: string;
    statusCode: number | null;
    title: string | null;
    server: string | null;
    tech: string[];
}
/**
 * httpx: probe a list of hosts for liveness + fingerprint. Auth header lines
 * are injected so probing goes past login. Input is fed via stdin.
 */
export declare function httpx(ctx: RunContext, hosts: string[]): Promise<HttpxResult[]>;
/** katana: active crawl of a single URL to discover endpoints. */
export declare function katana(ctx: RunContext, url: string): Promise<string[]>;
/** gau: pull historical URLs for a domain from public sources. */
export declare function gau(ctx: RunContext, domain: string): Promise<string[]>;
/** waybackurls: historical URLs from the Wayback Machine. */
export declare function waybackurls(ctx: RunContext, domain: string): Promise<string[]>;
/** naabu: light top-ports scan of one host for port context. */
export declare function naabu(ctx: RunContext, host: string): Promise<number[]>;
