// matrixView.ts — matrix RENDER helpers and types shared by the MatrixHeatmap
// component (Charts.tsx), Dashboard.tsx types, and the Help ExposureImpactGrid.
// Relocated from matrix.ts (Phase 4 — delete duplicated TS compute).
//
// NOTE: Tier is re-exported from metricsBundle.ts where it is the canonical
// definition (same union, same source of truth as the Go bundle JSON tags).
export type { Tier } from "./metricsBundle"
import type { Tier } from "./metricsBundle"

export const TIERS: Tier[] = ["Critical", "High", "Medium", "Low"]
export const IMPACT_UNKNOWN = "Unknown" as const

export type ImpactCol = Tier | typeof IMPACT_UNKNOWN
export const IMPACT_COLS: ImpactCol[] = [...TIERS, IMPACT_UNKNOWN]

export interface ExposureImpactMatrix {
  counts: Record<Tier, Record<ImpactCol, number>>
  total: number
  cell: (exp: Tier, imp: ImpactCol) => number
}

// LEVEL_MATRIX: the resulting risk Level for an (Exposure tier, Impact column)
// cell, transcribed verbatim from internal/risk/risk.go `levelMatrix` (whose rows
// are Impact and cols are Exposure) and re-keyed here as [exposure][impact] to match
// the dashboard's row=Exposure / col=Impact orientation. The Unknown column is
// risk.go's `impactKnown == false` branch: the Level is the Exposure tier ALONE
// (provisional). SINGLE SOURCE — both the live MatrixHeatmap and the Help
// ExposureImpactGrid read cellLevel(), so the grid colouring can't drift from the
// engine. Pinned cell-for-cell by matrixView.test.ts.
const LEVEL_MATRIX: Record<Tier, Record<ImpactCol, Tier>> = {
  Critical: { Critical: "Critical", High: "Critical", Medium: "High", Low: "Medium", Unknown: "Critical" },
  High:     { Critical: "Critical", High: "High",     Medium: "High", Low: "Medium", Unknown: "High" },
  Medium:   { Critical: "Critical", High: "High",     Medium: "Medium", Low: "Low",  Unknown: "Medium" },
  Low:      { Critical: "High",     High: "Medium",   Medium: "Medium", Low: "Low",  Unknown: "Low" },
}

// cellLevel: the risk Level an account lands in for a given (Exposure tier, Impact
// column). The Unknown column returns the Exposure-only (provisional) level.
export function cellLevel(exp: Tier, imp: ImpactCol): Tier {
  return LEVEL_MATRIX[exp][imp]
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
