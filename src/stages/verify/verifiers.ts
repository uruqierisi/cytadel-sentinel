import { httpRequest } from "../../lib/http.js";
import type { UnifiedFinding } from "../normalize/types.js";
import type { Verifier, VerificationResult, ReplayEvidence } from "./types.js";

/**
 * Verifier registry.
 *
 * ONE reference verifier is fully implemented (missing-security-header) to
 * demonstrate the deterministic, non-destructive replay pattern using
 * lib/http.ts. The remaining AUTO verifiers are declared as TODO stubs so the
 * Phase-2 wiring is obvious and type-safe.
 */

const HEADER_NAMES: Record<string, RegExp> = {
  "content-security-policy": /content-security-policy/i,
  "strict-transport-security": /strict-transport|hsts/i,
  "x-frame-options": /x-frame-options|clickjack/i,
  "x-content-type-options": /x-content-type/i,
};

function targetUrl(f: UnifiedFinding): string | null {
  const candidate = f.matchedLocation ?? f.target;
  try {
    const u = new URL(candidate);
    return u.protocol === "http:" || u.protocol === "https:" ? u.toString() : null;
  } catch {
    return null;
  }
}

function evidenceOf(
  requestLine: string,
  requestHeaders: Record<string, string>,
  res: Awaited<ReturnType<typeof httpRequest>>,
): ReplayEvidence {
  return {
    requestLine,
    requestHeaders,
    responseStatus: res.status,
    responseHeadersSnippet: res.headers,
    responseBodySnippet: res.body.slice(0, 500),
  };
}

/** FULLY IMPLEMENTED reference verifier: confirm a security header is absent. */
export const missingSecurityHeaderVerifier: Verifier = {
  id: "missing-security-header",
  applies(f) {
    const hay = `${f.templateId ?? ""} ${f.name}`.toLowerCase();
    return Object.values(HEADER_NAMES).some((re) => re.test(hay)) && targetUrl(f) !== null;
  },
  async verify(f, authHeaders): Promise<VerificationResult> {
    const url = targetUrl(f)!;
    const hay = `${f.templateId ?? ""} ${f.name}`.toLowerCase();
    const headerName =
      Object.keys(HEADER_NAMES).find((name) => HEADER_NAMES[name]!.test(hay)) ?? "content-security-policy";

    const res = await httpRequest(url, { method: "GET", headers: authHeaders });
    const present = res.headers[headerName] !== undefined;
    const evidence = evidenceOf(`GET ${url}`, authHeaders, res);

    // The finding claims the header is MISSING. Confirmed iff it is truly absent.
    return present
      ? { finding: f, classification: "AUTO", outcome: "LOW_CONFIDENCE", evidence, note: `${headerName} present on replay` }
      : { finding: f, classification: "AUTO", outcome: "VERIFIED", evidence, note: `${headerName} confirmed absent` };
  },
};

// TODO(Phase 2): implement the remaining AUTO verifiers using the same
// lib/http.ts replay pattern. Each must be deterministic + non-destructive.
//   - exposedEndpointVerifier      GET the path, confirm 200 + expected marker
//   - reflectedValueVerifier       send a benign unique token, confirm reflection
//   - openRedirectVerifier         confirm Location echoes an off-site host
//   - brokenAccessControlVerifier  request with/without auth, compare status
export const TODO_VERIFIERS: Verifier[] = [];

export const VERIFIERS: Verifier[] = [missingSecurityHeaderVerifier, ...TODO_VERIFIERS];
