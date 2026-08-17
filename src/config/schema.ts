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
export function isValidScopeDomain(d: string): boolean {
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
    type: z.enum(["cookie", "header", "none"]).default("none"),
    // Name of the env var that holds the secret — never the secret itself.
    session: z.string().trim().optional(),
  })
  .refine((a) => a.type === "none" || (a.session && a.session.length > 0), {
    message: 'auth.session (env var name) is required when auth.type is "cookie" or "header"',
    path: ["session"],
  });

export const ScopeSchema = z
  .object({
    name: z.string().trim().min(1),
    authorized_by: z.string().trim().min(1),
    authorization_ref: z.string().trim().min(1),
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
  })
  .strict();

export type Scope = z.infer<typeof ScopeSchema>;
export type ScopeAuth = z.infer<typeof AuthSchema>;
