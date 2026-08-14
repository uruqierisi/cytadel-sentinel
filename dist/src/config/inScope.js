/** Extract a lowercase host (no port) and optional path from any target form. */
function parseTarget(target) {
    const t = target.trim();
    if (t.length === 0)
        return null;
    // Full URL form.
    if (t.includes("://")) {
        try {
            const u = new URL(t);
            return { host: u.hostname.toLowerCase(), path: u.pathname || "/" };
        }
        catch {
            return null;
        }
    }
    // host or host:port (optionally with a trailing /path).
    const slash = t.indexOf("/");
    const hostPart = slash === -1 ? t : t.slice(0, slash);
    const pathPart = slash === -1 ? null : t.slice(slash);
    const host = hostPart.split(":")[0]?.toLowerCase() ?? "";
    if (host.length === 0)
        return null;
    return { host, path: pathPart };
}
/** Does `host` match a domain rule, which may be a "*.example.com" wildcard? */
function hostMatchesDomain(host, rule) {
    const r = rule.toLowerCase();
    if (r.startsWith("*.")) {
        const base = r.slice(2); // "example.com"
        // Wildcard matches any subdomain but NOT the apex itself.
        return host.endsWith("." + base) && host !== base;
    }
    return host === r;
}
/** Was this domain rule a wildcard? (for reason reporting) */
function isWildcard(rule) {
    return rule.startsWith("*.");
}
/**
 * Evaluate a target against the scope. Pure and synchronous — cheap to call on
 * every discovered asset.
 */
export function evaluateScope(scope, target) {
    const parsed = parseTarget(target);
    if (!parsed) {
        return { allowed: false, target, host: null, path: null, reason: "unparseable" };
    }
    const { host, path } = parsed;
    // 1) Exclusions win first — excluded domain.
    for (const rule of scope.exclusions.domains) {
        if (hostMatchesDomain(host, rule)) {
            return { allowed: false, target, host, path, reason: "excluded-domain" };
        }
    }
    // 2) Exclusions win — excluded path prefix (only relevant when we have a path).
    if (path) {
        for (const prefix of scope.exclusions.paths) {
            if (path.startsWith(prefix)) {
                return { allowed: false, target, host, path, reason: "excluded-path" };
            }
        }
    }
    // 3) Inclusion by explicit in_scope URL host.
    for (const url of scope.in_scope.urls) {
        try {
            const u = new URL(url);
            if (u.hostname.toLowerCase() === host) {
                return { allowed: true, target, host, path, reason: "matched-url" };
            }
        }
        catch {
            // ignore malformed (schema should have caught it)
        }
    }
    // 4) Inclusion by domain / wildcard.
    for (const rule of scope.in_scope.domains) {
        if (hostMatchesDomain(host, rule)) {
            return {
                allowed: true,
                target,
                host,
                path,
                reason: isWildcard(rule) ? "matched-wildcard" : "matched-domain",
            };
        }
    }
    return { allowed: false, target, host, path, reason: "no-match" };
}
/** Boolean convenience wrapper. Prefer evaluateScope() when you need the reason. */
export function isInScope(scope, target) {
    return evaluateScope(scope, target).allowed;
}
//# sourceMappingURL=inScope.js.map