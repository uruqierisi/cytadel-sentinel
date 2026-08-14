import { run, toolExists } from "../../lib/exec.js";
import { parseLines, parseJsonl } from "../../lib/parse.js";
import { audit } from "../../lib/audit.js";
/**
 * Thin, defensive wrappers around each recon binary. Every wrapper:
 *   - checks the tool exists (degrades to [] + a logged skip if not),
 *   - passes target data ONLY as argv or stdin (never a shell string),
 *   - audit-logs the TOOL_EXEC.
 *
 * Plain-text output modes are used where they are the most version-stable; only
 * httpx uses JSON because we need its structured fingerprint fields.
 */
async function ensure(ctx, tool, versionArgs) {
    const exists = await toolExists(tool, versionArgs ?? ["-version"]);
    if (!exists) {
        ctx.log.warn({ tool }, "recon: tool not installed — skipping (run scripts/setup.sh in WSL2/Linux)");
    }
    return exists;
}
async function logExec(ctx, tool, target) {
    await audit({
        runId: ctx.runId,
        actor: ctx.actor,
        action: "TOOL_EXEC",
        scopeHash: ctx.scopeHash,
        target,
        detail: { tool, stage: "recon" },
    });
}
/** subfinder: passive subdomain enumeration for one apex domain. */
export async function subfinder(ctx, domain) {
    if (!(await ensure(ctx, "subfinder")))
        return [];
    await logExec(ctx, "subfinder", domain);
    try {
        const { stdout } = await run("subfinder", ["-d", domain, "-silent"], {
            allowNonZeroExit: true,
            timeoutMs: 5 * 60 * 1000,
        });
        return parseLines(stdout);
    }
    catch (err) {
        ctx.log.error({ err, domain }, "subfinder failed");
        return [];
    }
}
/**
 * httpx: probe a list of hosts for liveness + fingerprint. Auth header lines
 * are injected so probing goes past login. Input is fed via stdin.
 */
export async function httpx(ctx, hosts) {
    if (hosts.length === 0)
        return [];
    if (!(await ensure(ctx, "httpx")))
        return [];
    await logExec(ctx, "httpx", `${hosts.length} hosts`);
    const args = [
        "-json",
        "-silent",
        "-sc", // status code
        "-title",
        "-td", // tech detect
        "-server",
        "-no-color",
        "-rate-limit",
        String(ctx.scope.rate_limit_rps),
    ];
    for (const line of ctx.auth.headerLines) {
        args.push("-H", line);
    }
    try {
        const { stdout } = await run("httpx", args, {
            input: hosts.join("\n") + "\n",
            allowNonZeroExit: true,
            timeoutMs: 10 * 60 * 1000,
        });
        return parseJsonl(stdout).map((r) => ({
            host: String(r["input"] ?? r["host"] ?? ""),
            url: String(r["url"] ?? ""),
            statusCode: typeof r["status_code"] === "number" ? r["status_code"] : null,
            title: r["title"] ?? null,
            server: r["webserver"] ?? r["server"] ?? null,
            tech: Array.isArray(r["tech"]) ? r["tech"] : [],
        }));
    }
    catch (err) {
        ctx.log.error({ err }, "httpx failed");
        return [];
    }
}
/** katana: active crawl of a single URL to discover endpoints. */
export async function katana(ctx, url) {
    if (!(await ensure(ctx, "katana")))
        return [];
    await logExec(ctx, "katana", url);
    const args = ["-u", url, "-silent", "-d", "2", "-jc", "-no-color", "-rl", String(ctx.scope.rate_limit_rps)];
    for (const line of ctx.auth.headerLines) {
        args.push("-H", line);
    }
    try {
        const { stdout } = await run("katana", args, { allowNonZeroExit: true, timeoutMs: 5 * 60 * 1000 });
        return parseLines(stdout);
    }
    catch (err) {
        ctx.log.error({ err, url }, "katana failed");
        return [];
    }
}
/** gau: pull historical URLs for a domain from public sources. */
export async function gau(ctx, domain) {
    if (!(await ensure(ctx, "gau", ["--version"])))
        return [];
    await logExec(ctx, "gau", domain);
    try {
        const { stdout } = await run("gau", ["--subs", domain], {
            allowNonZeroExit: true,
            timeoutMs: 3 * 60 * 1000,
        });
        return parseLines(stdout);
    }
    catch (err) {
        ctx.log.error({ err, domain }, "gau failed");
        return [];
    }
}
/** waybackurls: historical URLs from the Wayback Machine. */
export async function waybackurls(ctx, domain) {
    if (!(await ensure(ctx, "waybackurls", ["-h"])))
        return [];
    await logExec(ctx, "waybackurls", domain);
    try {
        const { stdout } = await run("waybackurls", [domain], {
            allowNonZeroExit: true,
            timeoutMs: 3 * 60 * 1000,
        });
        return parseLines(stdout);
    }
    catch (err) {
        ctx.log.error({ err, domain }, "waybackurls failed");
        return [];
    }
}
/** naabu: light top-ports scan of one host for port context. */
export async function naabu(ctx, host) {
    if (!(await ensure(ctx, "naabu")))
        return [];
    await logExec(ctx, "naabu", host);
    try {
        const { stdout } = await run("naabu", ["-host", host, "-top-ports", "100", "-silent", "-no-color"], { allowNonZeroExit: true, timeoutMs: 5 * 60 * 1000 });
        // Output lines are "host:port".
        const ports = new Set();
        for (const line of parseLines(stdout)) {
            const p = Number(line.split(":").pop());
            if (Number.isInteger(p) && p > 0)
                ports.add(p);
        }
        return [...ports].sort((a, b) => a - b);
    }
    catch (err) {
        ctx.log.error({ err, host }, "naabu failed");
        return [];
    }
}
//# sourceMappingURL=tools.js.map