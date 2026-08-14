/**
 * Deterministic classifier (fully implemented). Decides how a finding may be
 * verified. Conservative by design: anything that looks state-changing is
 * NEVER_AUTO, anything needing a browser/reasoning is MANUAL.
 */
const DESTRUCTIVE = /(sqli|sql-injection|rce|command-injection|deserial|ssti|xxe|upload|lfi|rfi|ssrf)/i;
const MANUAL = /(dom-xss|dom based|business-logic|logic-flaw|race-condition|csrf|oauth|chained)/i;
// Non-destructive, deterministic classes we can safely replay.
const AUTO_HINTS = [
    /missing.*header/i,
    /security-header/i,
    /(x-frame-options|content-security-policy|strict-transport|x-content-type)/i,
    /exposed|exposure|directory-listing|open-redirect/i,
    /reflected/i,
    /idor|broken-access|access-control|unauth(orized)?-access/i,
    /default-login|weak-cred/i,
];
export function classify(finding) {
    const hay = `${finding.templateId ?? ""} ${finding.name} ${finding.sourceTool}`.toLowerCase();
    if (DESTRUCTIVE.test(hay))
        return "NEVER_AUTO";
    if (MANUAL.test(hay))
        return "MANUAL";
    if (AUTO_HINTS.some((re) => re.test(hay)))
        return "AUTO";
    // testssl / retire findings are deterministic config/library facts — but they
    // are already confirmed by the tool, so we route them to MANUAL triage rather
    // than replaying (there's no single request that "proves" a weak cipher).
    return "MANUAL";
}
//# sourceMappingURL=classify.js.map