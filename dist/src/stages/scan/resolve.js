import path from "node:path";
import { existsSync } from "node:fs";
import { toolExists } from "../../lib/exec.js";
const TOOLS_DIR = path.resolve(process.cwd(), "tools");
export async function resolveNikto() {
    if (await toolExists("nikto", ["-Version"]))
        return { file: "nikto", baseArgs: [] };
    const pl = path.join(TOOLS_DIR, "nikto", "program", "nikto.pl");
    if (existsSync(pl) && (await toolExists("perl", ["-v"]))) {
        return { file: "perl", baseArgs: [pl] };
    }
    return null;
}
export async function resolveTestssl() {
    if (await toolExists("testssl.sh", ["--version"]))
        return { file: "testssl.sh", baseArgs: [] };
    const sh = path.join(TOOLS_DIR, "testssl.sh", "testssl.sh");
    if (existsSync(sh))
        return { file: sh, baseArgs: [] };
    return null;
}
/** dalfox (XSS) — active injection, destructive gate only. Installed via `go install`. */
export async function resolveDalfox() {
    if (await toolExists("dalfox", ["version"]))
        return { file: "dalfox", baseArgs: [] };
    return null;
}
/** sqlmap (SQLi) — active injection, destructive gate only. PATH or tools/sqlmap checkout. */
export async function resolveSqlmap() {
    if (await toolExists("sqlmap", ["--version"]))
        return { file: "sqlmap", baseArgs: [] };
    const py = path.join(TOOLS_DIR, "sqlmap", "sqlmap.py");
    if (existsSync(py)) {
        if (await toolExists("python3", ["--version"]))
            return { file: "python3", baseArgs: [py] };
        if (await toolExists("python", ["--version"]))
            return { file: "python", baseArgs: [py] };
    }
    return null;
}
//# sourceMappingURL=resolve.js.map