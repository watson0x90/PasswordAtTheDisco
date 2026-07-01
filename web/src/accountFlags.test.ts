import { describe, it, expect } from "vitest"
import type { Account } from "./api"
import { impactIsKnown, isProvisional, coverageState } from "./accountFlags"

// Minimal account factory — mirrors the pattern used across other test files.
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

describe("impactIsKnown", () => {
  it("true only when both impact_known=true AND impact_score is non-null", () => {
    expect(impactIsKnown(a({ impact_known: true, impact_score: 5 }))).toBe(true)
    expect(impactIsKnown(a({ impact_known: false, impact_score: 5 }))).toBe(false)
    expect(impactIsKnown(a({ impact_known: true, impact_score: null }))).toBe(false)
    expect(impactIsKnown(a({ impact_known: false, impact_score: null }))).toBe(false)
  })
})

describe("isProvisional", () => {
  it("true exactly when impact is unknown", () => {
    expect(isProvisional(a({ impact_known: false }))).toBe(true)
    expect(isProvisional(a({ impact_known: true, impact_score: 5 }))).toBe(false)
  })
  // Asymmetry guard: impact_known:true but impact_score:null is NOT a usable
  // number — must be treated as provisional, not as a zero-Impact reading.
  it("treats impact_known:true + impact_score:null as provisional", () => {
    expect(isProvisional(a({ impact_known: true, impact_score: null }))).toBe(true)
  })
})

describe("coverageState", () => {
  it("returns full for coverage:full and none for absent coverage", () => {
    expect(coverageState(a({ coverage: "full" }))).toBe("full")
    expect(coverageState(a({ coverage: "none" }))).toBe("none")
    expect(coverageState(a({}))).toBe("none") // omitempty absent => "none"
  })
})
