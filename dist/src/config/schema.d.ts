import { z } from "zod";
/** Accept an FQDN/wildcard, "localhost", or a bare IPv4 address (local lab testing). */
export declare function isValidScopeDomain(d: string): boolean;
export declare const AuthSchema: z.ZodEffects<z.ZodEffects<z.ZodObject<{
    type: z.ZodDefault<z.ZodEnum<["cookie", "header", "form_login", "none"]>>;
    session: z.ZodOptional<z.ZodString>;
    /** URL the login form/API POSTs to. */
    login_url: z.ZodOptional<z.ZodString>;
    /** Request field/JSON key for the username (e.g. "email"). */
    username_field: z.ZodOptional<z.ZodString>;
    /** Request field/JSON key for the password. */
    password_field: z.ZodOptional<z.ZodString>;
    /** ENV VAR NAME holding the username value (never the value itself). */
    username: z.ZodOptional<z.ZodString>;
    /** ENV VAR NAME holding the password value (never the value itself). */
    password: z.ZodOptional<z.ZodString>;
    /** Body encoding for the login request. */
    content_type: z.ZodDefault<z.ZodEnum<["form", "json"]>>;
    /**
     * Dot-path into a JSON login response to pull a bearer token, e.g.
     * "authentication.token" (Juice Shop). Session cookies are captured
     * automatically from Set-Cookie regardless.
     */
    token_json_pointer: z.ZodOptional<z.ZodString>;
    /**
     * Liveness modes, in priority: (1) success_status — the check URL returns
     * this status when authenticated; (2) success_indicator — a body substring
     * (or 3-digit status) that means logged-in; (3) DEFAULT (neither set) — a 2xx
     * that is NOT a 401/403, cross-checked against an anonymous request.
     */
    success_status: z.ZodOptional<z.ZodNumber>;
    success_indicator: z.ZodOptional<z.ZodString>;
    /**
     * URL to hit for the liveness check. Pick an endpoint that returns 401/403
     * when UNAUTHENTICATED so the auth/anon difference is detectable — e.g. a
     * protected resource, NOT an endpoint that returns 200 either way (Juice
     * Shop's /rest/user/whoami returns 200 anonymously and is a poor choice).
     */
    session_check_url: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    type: "cookie" | "header" | "form_login" | "none";
    content_type: "json" | "form";
    password?: string | undefined;
    session?: string | undefined;
    login_url?: string | undefined;
    username_field?: string | undefined;
    password_field?: string | undefined;
    username?: string | undefined;
    token_json_pointer?: string | undefined;
    success_status?: number | undefined;
    success_indicator?: string | undefined;
    session_check_url?: string | undefined;
}, {
    password?: string | undefined;
    type?: "cookie" | "header" | "form_login" | "none" | undefined;
    session?: string | undefined;
    login_url?: string | undefined;
    username_field?: string | undefined;
    password_field?: string | undefined;
    username?: string | undefined;
    content_type?: "json" | "form" | undefined;
    token_json_pointer?: string | undefined;
    success_status?: number | undefined;
    success_indicator?: string | undefined;
    session_check_url?: string | undefined;
}>, {
    type: "cookie" | "header" | "form_login" | "none";
    content_type: "json" | "form";
    password?: string | undefined;
    session?: string | undefined;
    login_url?: string | undefined;
    username_field?: string | undefined;
    password_field?: string | undefined;
    username?: string | undefined;
    token_json_pointer?: string | undefined;
    success_status?: number | undefined;
    success_indicator?: string | undefined;
    session_check_url?: string | undefined;
}, {
    password?: string | undefined;
    type?: "cookie" | "header" | "form_login" | "none" | undefined;
    session?: string | undefined;
    login_url?: string | undefined;
    username_field?: string | undefined;
    password_field?: string | undefined;
    username?: string | undefined;
    content_type?: "json" | "form" | undefined;
    token_json_pointer?: string | undefined;
    success_status?: number | undefined;
    success_indicator?: string | undefined;
    session_check_url?: string | undefined;
}>, {
    type: "cookie" | "header" | "form_login" | "none";
    content_type: "json" | "form";
    password?: string | undefined;
    session?: string | undefined;
    login_url?: string | undefined;
    username_field?: string | undefined;
    password_field?: string | undefined;
    username?: string | undefined;
    token_json_pointer?: string | undefined;
    success_status?: number | undefined;
    success_indicator?: string | undefined;
    session_check_url?: string | undefined;
}, {
    password?: string | undefined;
    type?: "cookie" | "header" | "form_login" | "none" | undefined;
    session?: string | undefined;
    login_url?: string | undefined;
    username_field?: string | undefined;
    password_field?: string | undefined;
    username?: string | undefined;
    content_type?: "json" | "form" | undefined;
    token_json_pointer?: string | undefined;
    success_status?: number | undefined;
    success_indicator?: string | undefined;
    session_check_url?: string | undefined;
}>;
export declare const ScopeSchema: z.ZodObject<{
    name: z.ZodString;
    authorized_by: z.ZodString;
    authorization_ref: z.ZodString;
    /** Client/organisation name for the report header (WP5). */
    client: z.ZodOptional<z.ZodString>;
    /** Prior run id to diff against for a retest report (WP5). */
    retest_of: z.ZodOptional<z.ZodString>;
    in_scope: z.ZodEffects<z.ZodObject<{
        domains: z.ZodDefault<z.ZodArray<z.ZodEffects<z.ZodString, string, string>, "many">>;
        urls: z.ZodDefault<z.ZodArray<z.ZodEffects<z.ZodString, string, string>, "many">>;
    }, "strip", z.ZodTypeAny, {
        domains: string[];
        urls: string[];
    }, {
        domains?: string[] | undefined;
        urls?: string[] | undefined;
    }>, {
        domains: string[];
        urls: string[];
    }, {
        domains?: string[] | undefined;
        urls?: string[] | undefined;
    }>;
    exclusions: z.ZodDefault<z.ZodObject<{
        domains: z.ZodDefault<z.ZodArray<z.ZodEffects<z.ZodString, string, string>, "many">>;
        paths: z.ZodDefault<z.ZodArray<z.ZodEffects<z.ZodString, string, string>, "many">>;
    }, "strip", z.ZodTypeAny, {
        paths: string[];
        domains: string[];
    }, {
        paths?: string[] | undefined;
        domains?: string[] | undefined;
    }>>;
    auth: z.ZodDefault<z.ZodEffects<z.ZodEffects<z.ZodObject<{
        type: z.ZodDefault<z.ZodEnum<["cookie", "header", "form_login", "none"]>>;
        session: z.ZodOptional<z.ZodString>;
        /** URL the login form/API POSTs to. */
        login_url: z.ZodOptional<z.ZodString>;
        /** Request field/JSON key for the username (e.g. "email"). */
        username_field: z.ZodOptional<z.ZodString>;
        /** Request field/JSON key for the password. */
        password_field: z.ZodOptional<z.ZodString>;
        /** ENV VAR NAME holding the username value (never the value itself). */
        username: z.ZodOptional<z.ZodString>;
        /** ENV VAR NAME holding the password value (never the value itself). */
        password: z.ZodOptional<z.ZodString>;
        /** Body encoding for the login request. */
        content_type: z.ZodDefault<z.ZodEnum<["form", "json"]>>;
        /**
         * Dot-path into a JSON login response to pull a bearer token, e.g.
         * "authentication.token" (Juice Shop). Session cookies are captured
         * automatically from Set-Cookie regardless.
         */
        token_json_pointer: z.ZodOptional<z.ZodString>;
        /**
         * Liveness modes, in priority: (1) success_status — the check URL returns
         * this status when authenticated; (2) success_indicator — a body substring
         * (or 3-digit status) that means logged-in; (3) DEFAULT (neither set) — a 2xx
         * that is NOT a 401/403, cross-checked against an anonymous request.
         */
        success_status: z.ZodOptional<z.ZodNumber>;
        success_indicator: z.ZodOptional<z.ZodString>;
        /**
         * URL to hit for the liveness check. Pick an endpoint that returns 401/403
         * when UNAUTHENTICATED so the auth/anon difference is detectable — e.g. a
         * protected resource, NOT an endpoint that returns 200 either way (Juice
         * Shop's /rest/user/whoami returns 200 anonymously and is a poor choice).
         */
        session_check_url: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        type: "cookie" | "header" | "form_login" | "none";
        content_type: "json" | "form";
        password?: string | undefined;
        session?: string | undefined;
        login_url?: string | undefined;
        username_field?: string | undefined;
        password_field?: string | undefined;
        username?: string | undefined;
        token_json_pointer?: string | undefined;
        success_status?: number | undefined;
        success_indicator?: string | undefined;
        session_check_url?: string | undefined;
    }, {
        password?: string | undefined;
        type?: "cookie" | "header" | "form_login" | "none" | undefined;
        session?: string | undefined;
        login_url?: string | undefined;
        username_field?: string | undefined;
        password_field?: string | undefined;
        username?: string | undefined;
        content_type?: "json" | "form" | undefined;
        token_json_pointer?: string | undefined;
        success_status?: number | undefined;
        success_indicator?: string | undefined;
        session_check_url?: string | undefined;
    }>, {
        type: "cookie" | "header" | "form_login" | "none";
        content_type: "json" | "form";
        password?: string | undefined;
        session?: string | undefined;
        login_url?: string | undefined;
        username_field?: string | undefined;
        password_field?: string | undefined;
        username?: string | undefined;
        token_json_pointer?: string | undefined;
        success_status?: number | undefined;
        success_indicator?: string | undefined;
        session_check_url?: string | undefined;
    }, {
        password?: string | undefined;
        type?: "cookie" | "header" | "form_login" | "none" | undefined;
        session?: string | undefined;
        login_url?: string | undefined;
        username_field?: string | undefined;
        password_field?: string | undefined;
        username?: string | undefined;
        content_type?: "json" | "form" | undefined;
        token_json_pointer?: string | undefined;
        success_status?: number | undefined;
        success_indicator?: string | undefined;
        session_check_url?: string | undefined;
    }>, {
        type: "cookie" | "header" | "form_login" | "none";
        content_type: "json" | "form";
        password?: string | undefined;
        session?: string | undefined;
        login_url?: string | undefined;
        username_field?: string | undefined;
        password_field?: string | undefined;
        username?: string | undefined;
        token_json_pointer?: string | undefined;
        success_status?: number | undefined;
        success_indicator?: string | undefined;
        session_check_url?: string | undefined;
    }, {
        password?: string | undefined;
        type?: "cookie" | "header" | "form_login" | "none" | undefined;
        session?: string | undefined;
        login_url?: string | undefined;
        username_field?: string | undefined;
        password_field?: string | undefined;
        username?: string | undefined;
        content_type?: "json" | "form" | undefined;
        token_json_pointer?: string | undefined;
        success_status?: number | undefined;
        success_indicator?: string | undefined;
        session_check_url?: string | undefined;
    }>>;
    rate_limit_rps: z.ZodDefault<z.ZodNumber>;
    allow_destructive: z.ZodDefault<z.ZodBoolean>;
    /** Target environment. Production destructive testing needs extra confirmation (WP6). */
    environment: z.ZodDefault<z.ZodEnum<["staging", "production"]>>;
    /**
     * Authorization WINDOW (WP6). A destructive run refuses to start outside
     * [start, end]. Datetimes are ISO-8601 (e.g. "2026-08-18T20:00:00Z").
     */
    authorization_window: z.ZodOptional<z.ZodObject<{
        start: z.ZodEffects<z.ZodString, string, string>;
        end: z.ZodEffects<z.ZodString, string, string>;
    }, "strip", z.ZodTypeAny, {
        start: string;
        end: string;
    }, {
        start: string;
        end: string;
    }>>;
    /** Rules-of-Engagement scan window: allowed weekdays (0=Sun..6=Sat) and hour range. */
    scan_window: z.ZodOptional<z.ZodObject<{
        days: z.ZodOptional<z.ZodArray<z.ZodNumber, "many">>;
        start_hour: z.ZodOptional<z.ZodNumber>;
        end_hour: z.ZodOptional<z.ZodNumber>;
    }, "strip", z.ZodTypeAny, {
        days?: number[] | undefined;
        start_hour?: number | undefined;
        end_hour?: number | undefined;
    }, {
        days?: number[] | undefined;
        start_hour?: number | undefined;
        end_hour?: number | undefined;
    }>>;
    /** Client emergency contact for the ROE / report. */
    emergency_contact: z.ZodOptional<z.ZodString>;
    /**
     * Known param URLs to inject DIRECTLY, bypassing recon discovery. Needed for
     * SPAs/APIs whose client-side/API routes katana/gau can't crawl (e.g. Juice
     * Shop /rest/products/search?q=). They still pass the scope gate, payload
     * cleaning, and signature dedupe like discovered param URLs.
     */
    seed_param_urls: z.ZodDefault<z.ZodArray<z.ZodEffects<z.ZodString, string, string>, "many">>;
    /**
     * Explicit OpenAPI/Swagger spec URLs to import (WP2). Common locations
     * (/swagger.json, /openapi.json, /api-docs, /v3/api-docs) are auto-probed
     * too. Parsed endpoints (method + example values) enter the injection set.
     */
    openapi_urls: z.ZodDefault<z.ZodArray<z.ZodEffects<z.ZodString, string, string>, "many">>;
}, "strict", z.ZodTypeAny, {
    name: string;
    authorized_by: string;
    authorization_ref: string;
    in_scope: {
        domains: string[];
        urls: string[];
    };
    exclusions: {
        paths: string[];
        domains: string[];
    };
    auth: {
        type: "cookie" | "header" | "form_login" | "none";
        content_type: "json" | "form";
        password?: string | undefined;
        session?: string | undefined;
        login_url?: string | undefined;
        username_field?: string | undefined;
        password_field?: string | undefined;
        username?: string | undefined;
        token_json_pointer?: string | undefined;
        success_status?: number | undefined;
        success_indicator?: string | undefined;
        session_check_url?: string | undefined;
    };
    rate_limit_rps: number;
    allow_destructive: boolean;
    environment: "staging" | "production";
    seed_param_urls: string[];
    openapi_urls: string[];
    client?: string | undefined;
    retest_of?: string | undefined;
    authorization_window?: {
        start: string;
        end: string;
    } | undefined;
    scan_window?: {
        days?: number[] | undefined;
        start_hour?: number | undefined;
        end_hour?: number | undefined;
    } | undefined;
    emergency_contact?: string | undefined;
}, {
    name: string;
    authorized_by: string;
    authorization_ref: string;
    in_scope: {
        domains?: string[] | undefined;
        urls?: string[] | undefined;
    };
    client?: string | undefined;
    retest_of?: string | undefined;
    exclusions?: {
        paths?: string[] | undefined;
        domains?: string[] | undefined;
    } | undefined;
    auth?: {
        password?: string | undefined;
        type?: "cookie" | "header" | "form_login" | "none" | undefined;
        session?: string | undefined;
        login_url?: string | undefined;
        username_field?: string | undefined;
        password_field?: string | undefined;
        username?: string | undefined;
        content_type?: "json" | "form" | undefined;
        token_json_pointer?: string | undefined;
        success_status?: number | undefined;
        success_indicator?: string | undefined;
        session_check_url?: string | undefined;
    } | undefined;
    rate_limit_rps?: number | undefined;
    allow_destructive?: boolean | undefined;
    environment?: "staging" | "production" | undefined;
    authorization_window?: {
        start: string;
        end: string;
    } | undefined;
    scan_window?: {
        days?: number[] | undefined;
        start_hour?: number | undefined;
        end_hour?: number | undefined;
    } | undefined;
    emergency_contact?: string | undefined;
    seed_param_urls?: string[] | undefined;
    openapi_urls?: string[] | undefined;
}>;
export type Scope = z.infer<typeof ScopeSchema>;
export type ScopeAuth = z.infer<typeof AuthSchema>;
