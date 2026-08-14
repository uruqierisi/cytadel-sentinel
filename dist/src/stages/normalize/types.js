/**
 * The unified finding schema. Every tool's raw output is normalized into this
 * shape before it is persisted or handed to DefectDojo. Keeping one schema is
 * what lets dedupe, verification, and reporting be tool-agnostic.
 */
/**
 * Dedupe key: sourceTool + templateId + host + matchedLocation.
 * Two findings with the same key are the same issue within a run; DefectDojo
 * additionally dedupes across runs.
 */
export function dedupeKey(f) {
    const parts = [
        f.sourceTool,
        f.templateId ?? f.name,
        hostOf(f.target),
        f.matchedLocation ?? "",
    ];
    return parts.join("|").toLowerCase();
}
/** Reduce a target/URL to a bare host for stable dedupe. */
export function hostOf(target) {
    try {
        if (target.includes("://"))
            return new URL(target).host.toLowerCase();
    }
    catch {
        /* fall through */
    }
    return target.split("/")[0]?.split(":")[0]?.toLowerCase() ?? target.toLowerCase();
}
/** Map an arbitrary tool severity string onto our enum. */
export function normalizeSeverity(input) {
    const s = (input ?? "").toLowerCase();
    if (s.startsWith("crit"))
        return "CRITICAL";
    if (s.startsWith("high"))
        return "HIGH";
    if (s.startsWith("med") || s === "moderate")
        return "MEDIUM";
    if (s.startsWith("low"))
        return "LOW";
    return "INFO";
}
//# sourceMappingURL=types.js.map