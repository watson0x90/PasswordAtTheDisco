// matrix.ts — pure-logic primitives shared by the v2 dashboard surfaces (matrix
// heatmap, coverage banner, table columns, drawer, worklist). No DOM, no React.
//
// The two-axis model (sub-project B): each account carries exposure_score (0–10,
// always) and impact_score (0–10 or null when Impact is Unknown — no BloodHound
// coverage). This module maps those scores to tiers, classifies coverage, counts
// accounts into the Exposure × Impact grid, and flags provisional (Unknown-impact)
// accounts. The design decisions referenced below are recorded in
// docs/superpowers/specs/2026-06-20-scoring-engine-v2-design.md:
//   D2 — impact_score null (or impact_known=false) ⇒ Impact Unknown;
//   D3 — coverage absent ⇒ "none";
//   D6 — tier cutoffs (≥8/≥6/≥4) mirror the Go engine exactly; Unknown is its own column.
import type { Account } from "./api"

export type Tier = "Critical" | "High" | "Medium" | "Low"
export const TIERS: Tier[] = ["Critical", "High", "Medium", "Low"]
export const IMPACT_UNKNOWN = "Unknown" as const

// axisTier mirrors B's per-axis cutoffs (>=8 Critical, >=6 High, >=4 Medium, else
// Low). This is documentation-only duplication of the 4 cutoffs (NOT the formula)
// from internal/risk/risk.go's tierOf; it is pinned by matrix.test.ts against the
// same boundary numbers as the Go golden tests so the two can't silently drift.
export function axisTier(v: number): Tier {
  if (v >= 8) return "Critical"
  if (v >= 6) return "High"
  if (v >= 4) return "Medium"
  return "Low"
}

// impactIsKnown: Impact is a usable number only when impact_known AND impact_score
// is non-null; both surfaces (provisional badge, matrix Unknown column) must use
// this so they can't drift.
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

export interface CoverageStats {
  enriched: number
  total: number
  partial: boolean
}
export function coverageStats(accts: Account[]): CoverageStats {
  const total = accts.length
  let enriched = 0
  for (const a of accts) if (coverageState(a) === "full") enriched++
  return { enriched, total, partial: total > 0 && enriched < total }
}

export type ImpactCol = Tier | typeof IMPACT_UNKNOWN
export const IMPACT_COLS: ImpactCol[] = [...TIERS, IMPACT_UNKNOWN]

export interface ExposureImpactMatrix {
  counts: Record<Tier, Record<ImpactCol, number>>
  total: number
  cell: (exp: Tier, imp: ImpactCol) => number
}

// exposureImpactMatrix: rows = Exposure tier, cols = Impact tier + an explicit
// Unknown column for impact_known=false accounts (which cannot be placed in an
// Impact tier). Tiers are derived from exposure_score / impact_score via axisTier.
export function exposureImpactMatrix(accts: Account[]): ExposureImpactMatrix {
  const counts = {} as Record<Tier, Record<ImpactCol, number>>
  for (const r of TIERS) {
    counts[r] = {} as Record<ImpactCol, number>
    for (const c of IMPACT_COLS) counts[r][c] = 0
  }
  let total = 0
  for (const a of accts) {
    const expT = axisTier(a.exposure_score)
    const impCol: ImpactCol =
      impactIsKnown(a) && a.impact_score !== null ? axisTier(a.impact_score) : IMPACT_UNKNOWN
    counts[expT][impCol]++
    total++
  }
  return { counts, total, cell: (exp, imp) => counts[exp][imp] }
}

// matrixMaxCount: the single largest cell count across the whole grid. Heatmap
// callers divide each cell by this to get a [0,1] intensity — kept here (tested)
// rather than computed in the component so the scale is pinned and never 0/NaN
// for an empty grid (returns 0, which callers guard before dividing).
export function matrixMaxCount(m: ExposureImpactMatrix): number {
  let max = 0
  for (const r of TIERS) for (const c of IMPACT_COLS) max = Math.max(max, m.counts[r][c])
  return max
}
