import { logger } from "../lib/logger.js";
export function emptyAuth() {
    return {
        enabled: false,
        mode: "none",
        headerLines: [],
        headerMap: {},
        cookie: null,
        nonCookieHeaderLines: [],
        redactedHeaderLines: [],
        degraded: false,
    };
}
/** Redact a header line's VALUE, keeping the name: "Cookie: abc" -> "Cookie: ***". */
export function redactHeaderLine(line) {
    const i = line.indexOf(":");
    if (i <= 0)
        return "***";
    return `${line.slice(0, i)}: ***`;
}
/** Build auth state from a raw cookie string. */
export function authFromCookie(cookie, mode = "cookie") {
    return {
        enabled: true,
        mode,
        headerLines: [`Cookie: ${cookie}`],
        headerMap: { Cookie: cookie },
        cookie,
        nonCookieHeaderLines: [],
        redactedHeaderLines: ["Cookie: ***"],
        degraded: false,
    };
}
/** Build auth state from a single "Name: value" header line. */
export function authFromHeaderLine(line, mode = "header") {
    const idx = line.indexOf(":");
    if (idx <= 0)
        return null;
    const name = line.slice(0, idx).trim();
    const val = line.slice(idx + 1).trim();
    if (!name || !val)
        return null;
    const isCookie = name.toLowerCase() === "cookie";
    return {
        enabled: true,
        mode,
        headerLines: [`${name}: ${val}`],
        headerMap: { [name]: val },
        cookie: isCookie ? val : null,
        nonCookieHeaderLines: isCookie ? [] : [`${name}: ${val}`],
        redactedHeaderLines: [`${name}: ***`],
        degraded: false,
    };
}
export function resolveAuth(scope) {
    const auth = scope.auth;
    if (auth.type === "none")
        return emptyAuth();
    // form_login is established asynchronously (network) at pipeline start; return
    // a disabled placeholder here so context construction stays synchronous.
    if (auth.type === "form_login") {
        return { ...emptyAuth(), mode: "form_login" };
    }
    if (!auth.session)
        return emptyAuth();
    const value = process.env[auth.session]?.trim();
    if (!value) {
        logger.warn({ envVar: auth.session, type: auth.type }, "auth configured but session env var is empty — proceeding UNAUTHENTICATED");
        return emptyAuth();
    }
    if (auth.type === "cookie")
        return authFromCookie(value);
    // type === "header": value is a full header line "Name: value".
    const built = authFromHeaderLine(value);
    if (!built) {
        logger.warn({ envVar: auth.session }, 'auth.type="header" but env value is not "Name: value" — ignoring');
        return emptyAuth();
    }
    return built;
}
//# sourceMappingURL=auth.js.map