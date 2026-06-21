import { describe, it, expect } from "vitest"
import type { Account } from "./api"
import { axisTier, coverageState, coverageStats, exposureImpactMatrix, isProvisional, IMPACT_UNKNOWN } from "./matrix"

// Mirrors the Account test factory used across web/src/*.test.ts (e.g. insights.test.ts):
// C1 set the factory default impact_known:false, so a test that wants a known Impact
// passes an explicit impact_score + impact_known:true.
const a = (p: Partial<Account>): Account =>
  ({
    username: "u",
    domain: "D",
    cracked: false,
    password_length: 0,
    risk_level: "Low",
    risk_score: 0,
    risk_vector: "",
    hibp_breached: false,
    hibp_breach_count: 0,
    da_domains: "None",
    controlled_object_count: 0,
    shared_with: 0,
    enabled: true,
    meets_policy: true,
    complexity: "",
    exposure_score: 0,
    impact_score: null,
    impact_known: false,
    ...p,
  }) as Account

describe("axisTier (mirrors B cutoffs: >=8 C, >=6 H, >=4 M, else L)", () => {
  it("maps boundaries", () => {
    expect(axisTier(8)).toBe("Critical")
    expect(axisTier(6)).toBe("High")
    expect(axisTier(4)).toBe("Medium")
    expect(axisTier(3.9)).toBe("Low")
    expect(axisTier(0)).toBe("Low")
  })
})

describe("isProvisional", () => {
  it("true exactly when impact_known is false", () => {
    expect(isProvisional(a({ impact_known: false }))).toBe(true)
    expect(isProvisional(a({ impact_known: true, impact_score: 5 }))).toBe(false)
  })
  // Asymmetry guard: impact_known:true but impact_score:null is NOT a usable
  // number, so the provisional badge and the matrix Unknown column must agree
  // via the shared impactIsKnown predicate (they keyed off different checks before).
  it("treats impact_known:true + impact_score:null as provisional AND routes it to matrix Unknown", () => {
    const acct = a({ exposure_score: 9, impact_known: true, impact_score: null })
    expect(isProvisional(acct)).toBe(true)
    const m = exposureImpactMatrix([acct])
    expect(m.cell("Critical", IMPACT_UNKNOWN)).toBe(1)
    // and it is NOT counted in any concrete Impact tier
    expect(m.cell("Critical", "Critical")).toBe(0)
  })
})

describe("coverageState", () => {
  it("returns full for coverage:full and none for absent coverage", () => {
    expect(coverageState(a({ coverage: "full" }))).toBe("full")
    expect(coverageState(a({}))).toBe("none")
  })
})

describe("coverageStats", () => {
  it("counts enriched (coverage full) over total; absent coverage => none", () => {
    const s = coverageStats([
      a({ coverage: "full" }),
      a({ coverage: "none" }),
      a({}), // absent => none
    ])
    expect(s.enriched).toBe(1)
    expect(s.total).toBe(3)
    expect(s.partial).toBe(true) // <100%
  })
  it("not partial when all enriched", () => {
    expect(coverageStats([a({ coverage: "full" })]).partial).toBe(false)
  })
  it("empty input => zeroed stats, not partial", () => {
    expect(coverageStats([])).toEqual({ enriched: 0, total: 0, partial: false })
  })
})

describe("exposureImpactMatrix", () => {
  it("places enriched accounts by (exposure tier, impact tier) and Unknown ones in the Unknown column", () => {
    const m = exposureImpactMatrix([
      a({ exposure_score: 9, impact_score: 9, impact_known: true }), // Crit x Crit
      a({ exposure_score: 6, impact_score: 4, impact_known: true }), // High x Med
      a({ exposure_score: 9, impact_score: null, impact_known: false }), // Crit x Unknown
    ])
    expect(m.cell("Critical", "Critical")).toBe(1)
    expect(m.cell("High", "Medium")).toBe(1)
    expect(m.cell("Critical", IMPACT_UNKNOWN)).toBe(1)
    expect(m.total).toBe(3)
  })
})
