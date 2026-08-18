import type { Severity } from "../normalize/types.js";

/**
 * CVSS v3.1 defaults + business impact (WP5).
 *
 * We derive a SANE DEFAULT vector/score per finding from its class (CWE) and
 * severity so every finding carries a CVSS v3.1 vector a client can trust as a
 * starting point. These are defaults, editable downstream (or in DefectDojo).
 * The business-impact line is deliberately separate from the technical severity.
 */

export interface Cvss {
  vector: string; // e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
  score: number; // 0.0 - 10.0
  severity: Severity; // qualitative band for the score
}

/** Per-class base vectors (network-exploitable web classes). */
const BY_CWE: Record<number, { vector: string; score: number }> = {
  // SQLi — high confidentiality+integrity impact.
  89: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", score: 9.1 },
  // Reflected XSS — user interaction, scope change, low C/I.
  79: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", score: 6.1 },
  // OS command injection.
  78: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 },
  // Path traversal.
  22: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 7.5 },
  // IDOR / broken object-level authz.
  639: { vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", score: 6.5 },
  // Information exposure.
  200: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score: 5.3 },
  // Missing security headers / config.
  693: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", score: 4.3 },
  1275: { vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", score: 3.7 },
};

/** Severity-band fallback vectors when the CWE is unknown. */
const BY_SEVERITY: Record<Severity, { vector: string; score: number }> = {
  CRITICAL: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 },
  HIGH: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", score: 8.6 },
  MEDIUM: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", score: 5.4 },
  LOW: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score: 3.7 },
  INFO: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", score: 0.0 },
};

function bandForScore(score: number): Severity {
  if (score === 0) return "INFO";
  if (score < 4) return "LOW";
  if (score < 7) return "MEDIUM";
  if (score < 9) return "HIGH";
  return "CRITICAL";
}

/** Derive a default CVSS v3.1 vector + score for a finding. */
export function cvssFor(opts: { cwe?: number | null; severity: Severity }): Cvss {
  const base = (opts.cwe != null && BY_CWE[opts.cwe]) || BY_SEVERITY[opts.severity];
  return { vector: base.vector, score: base.score, severity: bandForScore(base.score) };
}

/** A short, business-language impact line (separate from technical severity). */
export function businessImpactFor(opts: { cwe?: number | null; severity: Severity }): string {
  switch (opts.cwe) {
    case 89:
      return "An attacker could read or modify the application database — exposing customer data and enabling account takeover or data tampering.";
    case 79:
      return "An attacker could run code in victims' browsers to hijack sessions, steal data, or deface the application, damaging user trust.";
    case 78:
      return "An attacker could execute commands on the server, potentially taking full control of the host and any data it holds.";
    case 22:
      return "An attacker could read sensitive files from the server, exposing secrets, source, or other users' data.";
    case 639:
      return "A logged-in user could access or alter other users' records, breaching confidentiality and regulatory obligations.";
    case 200:
      return "Sensitive technical details are exposed that help an attacker plan a more targeted attack.";
    default:
      break;
  }
  switch (opts.severity) {
    case "CRITICAL":
    case "HIGH":
      return "Exploitation could lead to serious data exposure or loss of control of the affected system.";
    case "MEDIUM":
      return "Exploitation could weaken defenses or expose limited data, aiding a larger attack.";
    default:
      return "Low direct business impact, but worth fixing to reduce overall attack surface.";
  }
}
