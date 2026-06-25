import { describe, expect, it } from "vitest"
import { domainReport, domainSummary } from "./domainScope"
import type { Account, Report, ReportAccount, ReuseGroup, Summary } from "./api"

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

function ra(username: string, domain: string): ReportAccount {
  return {
    username, domain, cracked: true, risk_level: "High", risk_score: 5,
    hibp_breach_count: 0, shared_with: 0, controlled_object_count: 0, enabled: true,
  }
}

function group(id: number, memberDomains: string[]): ReuseGroup {
  return {
    group_id: id, size: memberDomains.length, cracked: true, hibp_breach_count: 0,
    has_da_pathway: false, domains: new Set(memberDomains).size,
    members: memberDomains.map((d, i) => ra(`m${id}_${i}`, d)),
  }
}

function emptyReport(over: Partial<Report>): Report {
  return {
    total_accounts: 0, cracked_count: 0, uncracked_count: 0, da_pathways: [], cracked: [],
    cracked_reuse: [], uncracked_reuse: [], hibp_exposed: [], weak_passwords: [],
    violation_counts: { common: 0, dictionary: 0, forbidden: 0, keyboard: 0 },
    escalated_by_shared_da: [], high_controlled: [], never_expires: [], stale_passwords: [],
    kerberoastable: [], asrep_roastable: [],
    ...over,
  }
}

describe("domainReport", () => {
  it("returns null when the org report is null", () => {
    expect(domainReport(null, "A.LOCAL")).toBeNull()
  })

  it("filters per-account lists to the domain", () => {
    const org = emptyReport({
      da_pathways: [ra("a", "A.LOCAL"), ra("b", "B.LOCAL")],
      cracked: [ra("a", "A.LOCAL"), ra("c", "A.LOCAL"), ra("d", "B.LOCAL")],
      hibp_exposed: [ra("d", "B.LOCAL")],
    })
    const d = domainReport(org, "A.LOCAL")!
    expect(d.da_pathways.map((x) => x.username)).toEqual(["a"])
    expect(d.cracked.map((x) => x.username)).toEqual(["a", "c"])
    expect(d.hibp_exposed).toEqual([])
  })

  it("keeps reuse groups with at least one member in the domain", () => {
    const org = emptyReport({
      cracked_reuse: [group(1, ["A.LOCAL", "B.LOCAL"]), group(2, ["B.LOCAL", "C.LOCAL"])],
    })
    const d = domainReport(org, "A.LOCAL")!
    expect(d.cracked_reuse.map((g) => g.group_id)).toEqual([1])
  })

  it("derives total/cracked/uncracked counts from the filtered domain accounts", () => {
    const org = emptyReport({ total_accounts: 99, cracked_count: 50, uncracked_count: 49 })
    const domainAccounts: Account[] = [
      { username: "a", domain: "A.LOCAL", cracked: true } as Account,
      { username: "b", domain: "A.LOCAL", cracked: false } as Account,
    ]
    const d = domainReport(org, "A.LOCAL", domainAccounts)!
    expect(d.total_accounts).toBe(2)
    expect(d.cracked_count).toBe(1)
    expect(d.uncracked_count).toBe(1)
  })

  it("passes violation_counts through unchanged", () => {
    const org = emptyReport({ violation_counts: { common: 3, dictionary: 2, forbidden: 1, keyboard: 0 } })
    const d = domainReport(org, "A.LOCAL")!
    expect(d.violation_counts).toEqual({ common: 3, dictionary: 2, forbidden: 1, keyboard: 0 })
  })
})
