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
//# sourceMappingURL=resolve.js.map