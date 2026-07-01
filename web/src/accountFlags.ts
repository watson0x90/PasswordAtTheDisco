// accountFlags.ts — per-account predicate functions shared by table, drawer, worklist,
// and coverage surfaces. These are NOT aggregate-compute; they classify a single account.
// Relocated from matrix.ts (Phase 4 — delete duplicated TS compute).
import type { Account } from "./api"

// impactIsKnown: Impact is a usable number only when impact_known AND impact_score
// is non-null; all surfaces (provisional badge, matrix Unknown column, axis-factor
// bars) must use this predicate so they can never drift from each other.
export function impactIsKnown(a: Account): boolean {
  return a.impact_known === true && a.impact_score !== null
}

// isProvisional: true exactly when Impact is Unknown (level was derived from
// Exposure alone). The UI shows a "provisional" badge and never claims a number
// for Impact.
export function isProvisional(a: Account): boolean {
  return !impactIsKnown(a)
}

// coverageState: absent coverage (omitempty) means no enrichment record => "none".
export function coverageState(a: Account): "full" | "none" {
  return a.coverage === "full" ? "full" : "none"
}
