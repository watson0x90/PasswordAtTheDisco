import { describe, it, expect } from "vitest"
import { cellLevel, matrixMaxCount, TIERS, IMPACT_COLS, IMPACT_UNKNOWN, type Tier, type ImpactCol, type ExposureImpactMatrix } from "./matrixView"

// Helper: build a minimal ExposureImpactMatrix without depending on the deleted
// exposureImpactMatrix() aggregate function. Only counts matter for matrixMaxCount.
function makeMatrix(cells: Partial<Record<Tier, Partial<Record<ImpactCol, number>>>>): ExposureImpactMatrix {
  const counts = {} as Record<Tier, Record<ImpactCol, number>>
  for (const r of TIERS) {
    counts[r] = {} as Record<ImpactCol, number>
    for (const c of IMPACT_COLS) counts[r][c] = cells[r]?.[c] ?? 0
  }
  return { counts, total: 0, cell: (exp, imp) => counts[exp][imp] }
}

describe("cellLevel (single source for risk.go levelMatrix; drives heatmap + Help grid)", () => {
  // Expected grid keyed [exposure][impact], transcribed from the risk.go table in
  // ExposureImpactGrid's header comment (rows=Impact there; re-keyed here).
  const EXPECT: Record<Tier, Record<Tier, Tier>> = {
    Critical: { Critical: "Critical", High: "Critical", Medium: "High", Low: "Medium" },
    High:     { Critical: "Critical", High: "High",     Medium: "High", Low: "Medium" },
    Medium:   { Critical: "Critical", High: "High",     Medium: "Medium", Low: "Low" },
    Low:      { Critical: "High",     High: "Medium",   Medium: "Medium", Low: "Low" },
  }
  it("matches the engine matrix for every Exposure × Impact tier cell", () => {
    for (const exp of TIERS) for (const imp of TIERS) expect(cellLevel(exp, imp)).toBe(EXPECT[exp][imp])
  })
  it("Unknown column takes the Exposure tier alone (provisional)", () => {
    for (const exp of TIERS) expect(cellLevel(exp, IMPACT_UNKNOWN)).toBe(exp)
  })
})

describe("matrixMaxCount (heatmap intensity scale)", () => {
  it("returns the single largest cell count across the whole grid", () => {
    const m = makeMatrix({ Critical: { Critical: 3, High: 1 }, High: { Medium: 1 } })
    expect(matrixMaxCount(m)).toBe(3)
  })
  it("returns 0 for an empty grid (no division-by-zero in callers)", () => {
    expect(matrixMaxCount(makeMatrix({}))).toBe(0)
  })
})

describe("TIERS / IMPACT_COLS / IMPACT_UNKNOWN constants", () => {
  it("TIERS has four entries in risk order", () => {
    expect(TIERS).toEqual(["Critical", "High", "Medium", "Low"])
  })
  it("IMPACT_COLS is TIERS + Unknown at the end", () => {
    expect(IMPACT_COLS).toEqual(["Critical", "High", "Medium", "Low", "Unknown"])
  })
  it("IMPACT_UNKNOWN is the string 'Unknown'", () => {
    expect(IMPACT_UNKNOWN).toBe("Unknown")
  })
})
