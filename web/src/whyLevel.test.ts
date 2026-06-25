import { describe, expect, it } from "vitest"
import { explainLevel } from "./whyLevel"
import type { Account } from "./api"

function base(over: Partial<Account>): Account {
  return {
    username: "u", domain: "CORP", risk_level: "Low", cracked: true,
    exposure_score: 3, impact_score: 2, shared_with: 0, hibp_breached: false,
    hibp_breach_count: 0, da_domains: "", controls_tier0: false,
    escalated_by_shared_da: false, escalated_by_mass_reuse: false,
    risk_score: 1, risk_vector: "", password_length: 8, complexity: "x",
    enabled: true, pwd_never_expires: false,
    ...over,
  } as Account
}

describe("explainLevel", () => {
  it("headlines Shared-DA", () => {
    const lines = explainLevel(base({ risk_level: "Critical", escalated_by_shared_da: true }))
    expect(lines[0]).toMatch(/Domain-Admin account/i)
  })
  it("headlines own DA path", () => {
    const lines = explainLevel(base({ risk_level: "Critical", da_domains: "CORP" }))
    expect(lines[0]).toMatch(/Domain-Admin attack path/i)
  })
  it("headlines Tier-0 control", () => {
    const lines = explainLevel(base({ risk_level: "High", controls_tier0: true }))
    expect(lines[0]).toMatch(/Tier-0/i)
  })
  it("headlines mass-reuse", () => {
    const lines = explainLevel(base({ risk_level: "High", escalated_by_mass_reuse: true }))
    expect(lines[0]).toMatch(/reuse cluster/i)
  })
  it("falls back to the Exposure x Impact matrix", () => {
    const lines = explainLevel(base({ risk_level: "Medium", exposure_score: 4.8, impact_score: 5 }))
    expect(lines[0]).toMatch(/Exposure .* Impact/i)
  })
})
