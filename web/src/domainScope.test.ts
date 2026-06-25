import { describe, expect, it } from "vitest"
import { domainSummary } from "./domainScope"
import type { Account, Summary } from "./api"

// Minimal Account factory — only the fields the builders read.
function acc(over: Partial<Account>): Account {
  return {
    username: "u", domain: "A.LOCAL", cracked: false, password_length: 0,
    risk_level: "Low", risk_score: 0, exposure_score: 0, impact_score: null,
    impact_known: false, percentile: 0, risk_vector: "", hibp_breached: false,
    hibp_breach_count: 0, da_domains: "", controlled_object_count: 0, shared_with: 0,
    enabled: true, meets_policy: true, complexity: "",
    ...over,
  }
}

const orgSummary = { generated_at: "2026-06-20T10:00:00Z" } as Summary

describe("domainSummary", () => {
  it("counts only the passed (already-domain-filtered) accounts", () => {
    const domainAccounts: Account[] = [
      acc({ username: "a", domain: "A.LOCAL", cracked: true, meets_policy: false, hibp_breached: true, hibp_breach_count: 5 }),
      acc({ username: "b", domain: "A.LOCAL", cracked: true, da_domains: "A.LOCAL", controlled_object_count: 200 }),
      acc({ username: "c", domain: "A.LOCAL", enabled: false, pwd_never_expires: true }),
      acc({ username: "d", domain: "A.LOCAL", days_out_of_compliance: 30 }),
    ]
    const s = domainSummary(domainAccounts, orgSummary)
    expect(s.total_accounts).toBe(4)
    expect(s.cracked).toBe(2)
    expect(s.hibp_breached).toBe(1)
    expect(s.da_pathways).toBe(1)
    expect(s.disabled_accounts).toBe(1)
    expect(s.never_expires).toBe(1)
    expect(s.stale_passwords).toBe(1)
    expect(s.policy_violations).toBe(1) // cracked && !meets_policy
    expect(s.high_controlled).toBe(1)   // controlled_object_count > 100
  })

  it("omits breach_impact and copies generated_at from the org summary", () => {
    const s = domainSummary([acc({})], orgSummary)
    expect(s.breach_impact).toBeUndefined()
    expect(s.generated_at).toBe("2026-06-20T10:00:00Z")
  })

  it("tallies risk_counts by risk_level and attaches a posture", () => {
    const s = domainSummary(
      [acc({ risk_level: "Critical" }), acc({ risk_level: "Critical" }), acc({ risk_level: "Low" })],
      orgSummary,
    )
    expect(s.risk_counts).toEqual({ Critical: 2, Low: 1 })
    expect(s.posture).toBeDefined()
    expect(typeof s.posture.score).toBe("number")
  })

  it("counts dormant_privileged as disabled, privileged, credential-obtainable accounts", () => {
    const s = domainSummary(
      [
        acc({ enabled: false, controls_tier0: true, cracked: true }),   // dormant privileged ✓
        acc({ enabled: false, controls_tier0: true }),                  // privileged but NOT credential-obtainable ✗
        acc({ enabled: false, cracked: true }),                         // credential-obtainable but NOT privileged ✗
        acc({ enabled: true, controls_tier0: true, cracked: true }),    // privileged+obtainable but ENABLED ✗
        acc({ enabled: false, da_domains: "A.LOCAL", hibp_breached: true }), // disabled+DA-path+breached ✓
      ],
      orgSummary,
    )
    expect(s.dormant_privileged).toBe(2)
  })
})
