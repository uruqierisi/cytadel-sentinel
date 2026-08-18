import { z } from "zod";
/**
 * Zod schema for a scope file. Validation happens at the system boundary
 * (load time) — nothing downstream trusts an unvalidated scope.
 */
// FQDN, optionally wildcarded: "example.com" / "*.example.com".
const fqdnPattern = /^(\*\.)?([a-z0-9-]+\.)+[a-z]{2,}$/i;
// Bare IPv4 with each octet 0-255: "127.0.0.1", "10.0.0.5", "192.168.1.20".
const ipv4Octet = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const ipv4Pattern = new RegExp(`^${ipv4Octet}(\\.${ipv4Octet}){3}$`);
/** Accept an FQDN/wildcard, "localhost", or a bare IPv4 address (local lab testing). */
export function isValidScopeDomain(d) {
    return d === "localhost" || fqdnPattern.test(d) || ipv4Pattern.test(d);
}
const DomainSchema = z
    .string()
    .trim()
    .toLowerCase()
    .refine(isValidScopeDomain, {
    message: 'invalid domain (use "example.com", wildcard "*.example.com", "localhost", or an IPv4 like "127.0.0.1")',
});
const UrlSchema = z
    .string()
    .trim()
    .url()
    .refine((u) => u.startsWith("http://") || u.startsWith("https://"), {
    message: "url must be http(s)",
});
const PathPrefixSchema = z
    .string()
    .trim()
    .refine((p) => p.startsWith("/"), { message: "path prefix must start with /" });
export const AuthSchema = z
    .object({
    type: z.enum(["cookie", "header", "form_login", "none"]).default("none"),
    // Name of the env var that holds the secret — never the secret itself.
    session: z.string().trim().optional(),
    // --- form_login (type: "form_login") ---
    /** URL the login form/API POSTs to. */
    login_url: z.string().trim().url().optional(),
    /** Request field/JSON key for the username (e.g. "email"). */
    username_field: z.string().trim().optional(),
    /** Request field/JSON key for the password. */
    password_field: z.string().trim().optional(),
    /** ENV VAR NAME holding the username value (never the value itself). */
    username: z.string().trim().optional(),
    /** ENV VAR NAME holding the password value (never the value itself). */
    password: z.string().trim().optional(),
    /** Body encoding for the login request. */
    content_type: z.enum(["form", "json"]).default("form"),
    /**
     * Dot-path into a JSON login response to pull a bearer token, e.g.
     * "authentication.token" (Juice Shop). Session cookies are captured
     * automatically from Set-Cookie regardless.
     */
    token_json_pointer: z.string().trim().optional(),
    /**
     * Liveness modes, in priority: (1) success_status — the check URL returns
     * this status when authenticated; (2) success_indicator — a body substring
     * (or 3-digit status) that means logged-in; (3) DEFAULT (neither set) — a 2xx
     * that is NOT a 401/403, cross-checked against an anonymous request.
     */
    success_status: z.number().int().min(100).max(599).optional(),
    success_indicator: z.string().trim().optional(),
    /**
     * URL to hit for the liveness check. Pick an endpoint that returns 401/403
     * when UNAUTHENTICATED so the auth/anon difference is detectable — e.g. a
     * protected resource, NOT an endpoint that returns 200 either way (Juice
     * Shop's /rest/user/whoami returns 200 anonymously and is a poor choice).
     */
    session_check_url: z.string().trim().url().optional(),
})
    .refine((a) => a.type !== "cookie" && a.type !== "header" ? true : Boolean(a.session && a.session.length > 0), {
    message: 'auth.session (env var name) is required when auth.type is "cookie" or "header"',
    path: ["session"],
})
    .refine((a) => a.type !== "form_login" ||
    Boolean(a.login_url && a.username_field && a.password_field && a.username && a.password), {
    message: 'auth.type "form_login" requires login_url, username_field, password_field, username (env var name), password (env var name)',
    path: ["type"],
});
export const ScopeSchema = z
    .object({
    name: z.string().trim().min(1),
    authorized_by: z.string().trim().min(1),
    authorization_ref: z.string().trim().min(1),
    /** Client/organisation name for the report header (WP5). */
    client: z.string().trim().optional(),
    /** Prior run id to diff against for a retest report (WP5). */
    retest_of: z.string().trim().optional(),
    in_scope: z
        .object({
        domains: z.array(DomainSchema).default([]),
        urls: z.array(UrlSchema).default([]),
    })
        .refine((s) => s.domains.length > 0 || s.urls.length > 0, {
        message: "in_scope must define at least one domain or url",
    }),
    exclusions: z
        .object({
        domains: z.array(DomainSchema).default([]),
        paths: z.array(PathPrefixSchema).default([]),
    })
        .default({ domains: [], paths: [] }),
    auth: AuthSchema.default({ type: "none" }),
    rate_limit_rps: z.number().int().positive().max(1000).default(10),
    allow_destructive: z.boolean().default(false),
    /** Target environment. Production destructive testing needs extra confirmation (WP6). */
    environment: z.enum(["staging", "production"]).default("staging"),
    /**
     * Authorization WINDOW (WP6). A destructive run refuses to start outside
     * [start, end]. Datetimes are ISO-8601 (e.g. "2026-08-18T20:00:00Z").
     */
    authorization_window: z
        .object({
        start: z.string().trim().refine((s) => !Number.isNaN(Date.parse(s)), { message: "start must be a valid datetime" }),
        end: z.string().trim().refine((s) => !Number.isNaN(Date.parse(s)), { message: "end must be a valid datetime" }),
    })
        .optional(),
    /** Rules-of-Engagement scan window: allowed weekdays (0=Sun..6=Sat) and hour range. */
    scan_window: z
        .object({
        days: z.array(z.number().int().min(0).max(6)).optional(),
        start_hour: z.number().int().min(0).max(23).optional(),
        end_hour: z.number().int().min(1).max(24).optional(),
    })
        .optional(),
    /** Client emergency contact for the ROE / report. */
    emergency_contact: z.string().trim().optional(),
    /**
     * Known param URLs to inject DIRECTLY, bypassing recon discovery. Needed for
     * SPAs/APIs whose client-side/API routes katana/gau can't crawl (e.g. Juice
     * Shop /rest/products/search?q=). They still pass the scope gate, payload
     * cleaning, and signature dedupe like discovered param URLs.
     */
    seed_param_urls: z.array(UrlSchema).default([]),
    /**
     * Explicit OpenAPI/Swagger spec URLs to import (WP2). Common locations
     * (/swagger.json, /openapi.json, /api-docs, /v3/api-docs) are auto-probed
     * too. Parsed endpoints (method + example values) enter the injection set.
     */
    openapi_urls: z.array(UrlSchema).default([]),
})
    .strict();
//# sourceMappingURL=schema.js.map