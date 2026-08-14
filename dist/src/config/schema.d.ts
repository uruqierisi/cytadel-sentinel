import { z } from "zod";
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
}>;
export type Scope = z.infer<typeof ScopeSchema>;
export type ScopeAuth = z.infer<typeof AuthSchema>;
