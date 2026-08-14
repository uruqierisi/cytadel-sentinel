import { logger } from "../lib/logger.js";
const EMPTY = { enabled: false, headerLines: [], headerMap: {} };
export function resolveAuth(scope) {
    const auth = scope.auth;
    if (auth.type === "none" || !auth.session)
        return EMPTY;
    const value = process.env[auth.session]?.trim();
    if (!value) {
        logger.warn({ envVar: auth.session, type: auth.type }, "auth configured but session env var is empty — proceeding UNAUTHENTICATED");
        return EMPTY;
    }
    if (auth.type === "cookie") {
        const line = `Cookie: ${value}`;
        return { enabled: true, headerLines: [line], headerMap: { Cookie: value } };
    }
    // type === "header": value is a full header line "Name: value".
    const idx = value.indexOf(":");
    if (idx <= 0) {
        logger.warn({ envVar: auth.session }, 'auth.type="header" but env value is not "Name: value" — ignoring');
        return EMPTY;
    }
    const name = value.slice(0, idx).trim();
    const val = value.slice(idx + 1).trim();
    return { enabled: true, headerLines: [`${name}: ${val}`], headerMap: { [name]: val } };
}
//# sourceMappingURL=auth.js.map