import type { Scope } from "../config/schema.js";

/**
 * Engagement governance (WP6).
 *
 * Destructive testing against a client is a legal act, so it needs more than the
 * technical destructive gate (scope allow_destructive + --allow-destructive). It
 * also requires a valid authorization record within an authorization WINDOW, must
 * respect the Rules-of-Engagement scan window, and — against production — an
 * explicit human confirmation. All decisions here are pure/testable; the
 * orchestrator turns them into hard refusals (AUTHZ_REJECTED) or soft skips.
 */

export interface GovDecision {
  allowed: boolean;
  reason: string;
}

function parse(dt: string): number {
  return Date.parse(dt);
}

/**
 * Authorization gate for a DESTRUCTIVE run: requires an authorization reference
 * and a time window, and the current time must fall inside it. Non-destructive
 * runs are always allowed.
 */
export function evaluateAuthorization(scope: Scope, allowDestructive: boolean, now: Date): GovDecision {
  if (!allowDestructive) return { allowed: true, reason: "non-destructive run — authorization window not required" };
  if (!scope.authorization_ref || scope.authorization_ref.trim().length === 0) {
    return { allowed: false, reason: "no authorization reference — a destructive run requires a contract/letter id" };
  }
  const w = scope.authorization_window;
  if (!w) {
    return { allowed: false, reason: "no authorization_window defined — a destructive run must be time-boxed by written authorization" };
  }
  const t = now.getTime();
  const start = parse(w.start);
  const end = parse(w.end);
  if (Number.isNaN(start) || Number.isNaN(end)) {
    return { allowed: false, reason: "authorization_window start/end is not a valid datetime" };
  }
  if (t < start) return { allowed: false, reason: `outside authorization window — before start ${w.start}` };
  if (t > end) return { allowed: false, reason: `outside authorization window — after end ${w.end}` };
  return { allowed: true, reason: `within authorization window (${w.start} → ${w.end})` };
}

/**
 * Rules-of-Engagement scan window: allowed weekdays (0=Sun..6=Sat) and/or an
 * hour range [start_hour, end_hour). Only enforced for destructive runs. Absent
 * fields are unrestricted.
 */
export function evaluateScanWindow(scope: Scope, allowDestructive: boolean, now: Date): GovDecision {
  if (!allowDestructive) return { allowed: true, reason: "non-destructive run — scan window not enforced" };
  const sw = scope.scan_window;
  if (!sw) return { allowed: true, reason: "no scan_window restriction" };
  if (sw.days && sw.days.length > 0 && !sw.days.includes(now.getDay())) {
    return { allowed: false, reason: `outside RoE scan window — day ${now.getDay()} not in allowed days [${sw.days.join(",")}]` };
  }
  if (sw.start_hour != null && sw.end_hour != null) {
    const h = now.getHours();
    if (h < sw.start_hour || h >= sw.end_hour) {
      return { allowed: false, reason: `outside RoE scan window — hour ${h} not in [${sw.start_hour},${sw.end_hour})` };
    }
  }
  return { allowed: true, reason: "within RoE scan window" };
}

/**
 * Production safety gate. Destructive testing against a production environment is
 * BLOCKED unless the operator explicitly confirms with --i-understand-production.
 * Returns whether injection is blocked (soft skip) and why.
 */
export function evaluateProductionGate(
  scope: Scope,
  allowDestructive: boolean,
  confirmProduction: boolean,
): { blocked: boolean; reason: string } {
  if (!allowDestructive || scope.environment !== "production") {
    return { blocked: false, reason: "not a production destructive run" };
  }
  if (confirmProduction) {
    return { blocked: false, reason: "production destructive testing explicitly confirmed (--i-understand-production)" };
  }
  return {
    blocked: true,
    reason: "environment is PRODUCTION and destructive testing was not explicitly confirmed — pass --i-understand-production to proceed",
  };
}
