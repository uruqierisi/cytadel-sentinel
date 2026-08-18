/**
 * Remediation guidance (WP5).
 *
 * A maintainable CWE/type -> guidance map so every finding carries concrete,
 * consistent fix advice. Edit the map to tune wording; findings look up by CWE
 * first, then fall back to a source-tool default, then a generic default.
 */

export interface Remediation {
  /** One-line summary of the fix. */
  summary: string;
  /** Concrete, actionable steps. */
  guidance: string;
}

/** CWE id -> remediation. Keep entries short, concrete, and vendor-neutral. */
const BY_CWE: Record<number, Remediation> = {
  89: {
    summary: "Use parameterized queries / prepared statements for all database access.",
    guidance:
      "Never build SQL by string concatenation with user input. Use parameterized queries " +
      "(prepared statements) or a well-configured ORM so values are bound, not interpolated. " +
      "Apply least-privilege DB accounts, validate/allow-list input types, and disable verbose " +
      "SQL error messages in production.",
  },
  79: {
    summary: "Contextually output-encode untrusted data and deploy a strict Content-Security-Policy.",
    guidance:
      "Encode user-controlled data for the exact output context (HTML, attribute, JS, URL) using " +
      "a framework's auto-escaping. Avoid innerHTML/dangerouslySetInnerHTML with untrusted input. " +
      "Add a strict CSP (no unsafe-inline), set HttpOnly/SameSite cookies, and sanitize rich text " +
      "with a vetted library (e.g. DOMPurify).",
  },
  78: {
    summary: "Avoid shelling out; if unavoidable, use argument arrays and strict allow-lists.",
    guidance:
      "Do not pass user input to a shell. Use APIs that take an argument array (no shell), " +
      "allow-list permitted values, and drop OS privileges. Validate every parameter.",
  },
  22: {
    summary: "Canonicalize and confine file paths to an allowed base directory.",
    guidance:
      "Resolve the requested path and verify it stays within an intended base directory; reject " +
      "'..' traversal. Prefer opaque identifiers mapped server-side to real paths.",
  },
  639: {
    summary: "Enforce per-object authorization on every request (IDOR).",
    guidance:
      "Check that the authenticated principal owns/may access the referenced object on the server " +
      "for every request. Do not rely on unguessable IDs alone; use indirect references and deny by default.",
  },
  200: {
    summary: "Remove sensitive data from responses, errors, and headers.",
    guidance:
      "Return only what the client needs. Suppress stack traces and internal identifiers in production, " +
      "and strip version/banner headers that aid targeting.",
  },
  1275: {
    summary: "Set secure cookie attributes (HttpOnly, Secure, SameSite).",
    guidance: "Mark session cookies HttpOnly and Secure, and set SameSite=Lax or Strict to limit CSRF/XSS impact.",
  },
  693: {
    summary: "Add the missing security headers.",
    guidance:
      "Set Content-Security-Policy, X-Content-Type-Options: nosniff, Strict-Transport-Security, " +
      "Referrer-Policy, and a restrictive Permissions-Policy.",
  },
  16: {
    summary: "Harden the server/application configuration.",
    guidance: "Disable directory listing, remove default/sample content, and review exposed admin or debug endpoints.",
  },
};

/** Source-tool fallbacks when a CWE has no explicit entry. */
const BY_TOOL: Record<string, Remediation> = {
  sqlmap: BY_CWE[89]!,
  dalfox: BY_CWE[79]!,
  testssl: {
    summary: "Fix the TLS configuration.",
    guidance:
      "Disable weak protocols (SSLv3/TLS1.0/1.1) and ciphers, deploy a valid certificate chain, " +
      "enable HSTS, and prefer forward-secret cipher suites.",
  },
  retirejs: {
    summary: "Upgrade the vulnerable JavaScript dependency.",
    guidance:
      "Update the flagged library to a fixed version, remove unused libraries, and add SCA to CI so " +
      "vulnerable dependencies are caught before release.",
  },
  nikto: {
    summary: "Review the flagged server exposure.",
    guidance: "Remove obsolete files, restrict admin/debug paths, and apply the missing hardening the scanner reported.",
  },
};

const GENERIC: Remediation = {
  summary: "Validate the finding and apply defense-in-depth.",
  guidance:
    "Confirm the issue manually, fix the root cause, and add input validation, output encoding, " +
    "authorization checks, and security headers as appropriate for the affected component.",
};

/** Extract a CWE id from a finding's cwe field/title (e.g. "CWE-89" or 89). */
export function cweOf(cwe: number | string | null | undefined): number | null {
  if (typeof cwe === "number" && Number.isFinite(cwe)) return cwe;
  if (typeof cwe === "string") {
    const n = Number(cwe.replace(/\D+/g, ""));
    return Number.isFinite(n) && n > 0 ? n : null;
  }
  return null;
}

/** Resolve remediation for a finding: CWE first, then source tool, then generic. */
export function remediationFor(opts: { cwe?: number | string | null; sourceTool?: string }): Remediation {
  const cwe = cweOf(opts.cwe);
  if (cwe && BY_CWE[cwe]) return BY_CWE[cwe]!;
  const tool = (opts.sourceTool ?? "").toLowerCase();
  if (BY_TOOL[tool]) return BY_TOOL[tool]!;
  return GENERIC;
}
