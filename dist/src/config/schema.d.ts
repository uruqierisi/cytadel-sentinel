import { z } from "zod";
/** Accept an FQDN/wildcard, "localhost", or a bare IPv4 address (local lab testing). */
export declare function isValidScopeDomain(d: string): boolean;
export declare const AuthSchema: z.ZodEffects<z.ZodObject<{
    type: z.ZodDefault<z.ZodEnum<["cookie", "header", "none"]>>;
    session: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    type: "cookie" | "header" | "none";
    session?: string | undefined;
}, {
    type?: "cookie" | "header" | "none" | undefined;
    session?: string | undefined;
}>, {
    type: "cookie" | "header" | "none";
    session?: string | undefined;
}, {
    type?: "cookie" | "header" | "none" | undefined;
    session?: string | undefined;
}>;
export declare const ScopeSchema: z.ZodObject<{
    name: z.ZodString;
    authorized_by: z.ZodString;
    authorization_ref: z.ZodString;
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
        domains: string[];
        paths: string[];
    }, {
        domains?: string[] | undefined;
        paths?: string[] | undefined;
    }>>;
    auth: z.ZodDefault<z.ZodEffects<z.ZodObject<{
        type: z.ZodDefault<z.ZodEnum<["cookie", "header", "none"]>>;
        session: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        type: "cookie" | "header" | "none";
        session?: string | undefined;
    }, {
        type?: "cookie" | "header" | "none" | undefined;
        session?: string | undefined;
    }>, {
        type: "cookie" | "header" | "none";
        session?: string | undefined;
    }, {
        type?: "cookie" | "header" | "none" | undefined;
        session?: string | undefined;
    }>>;
    rate_limit_rps: z.ZodDefault<z.ZodNumber>;
    allow_destructive: z.ZodDefault<z.ZodBoolean>;
    /**
     * Known param URLs to inject DIRECTLY, bypassing recon discovery. Needed for
     * SPAs/APIs whose client-side/API routes katana/gau can't crawl (e.g. Juice
     * Shop /rest/products/search?q=). They still pass the scope gate, payload
     * cleaning, and signature dedupe like discovered param URLs.
     */
    seed_param_urls: z.ZodDefault<z.ZodArray<z.ZodEffects<z.ZodString, string, string>, "many">>;
}, "strict", z.ZodTypeAny, {
    name: string;
    authorized_by: string;
    authorization_ref: string;
    in_scope: {
        domains: string[];
        urls: string[];
    };
    exclusions: {
        domains: string[];
        paths: string[];
    };
    auth: {
        type: "cookie" | "header" | "none";
        session?: string | undefined;
    };
    rate_limit_rps: number;
    allow_destructive: boolean;
    seed_param_urls: string[];
}, {
    name: string;
    authorized_by: string;
    authorization_ref: string;
    in_scope: {
        domains?: string[] | undefined;
        urls?: string[] | undefined;
    };
    exclusions?: {
        domains?: string[] | undefined;
        paths?: string[] | undefined;
    } | undefined;
    auth?: {
        type?: "cookie" | "header" | "none" | undefined;
        session?: string | undefined;
    } | undefined;
    rate_limit_rps?: number | undefined;
    allow_destructive?: boolean | undefined;
    seed_param_urls?: string[] | undefined;
}>;
export type Scope = z.infer<typeof ScopeSchema>;
export type ScopeAuth = z.infer<typeof AuthSchema>;
