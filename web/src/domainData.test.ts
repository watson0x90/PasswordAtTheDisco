import { describe, it, expect } from "vitest"
import { domainReuseClusters, domainDAPaths, domainQuickWins, domainPolicy, domainWordlist } from "./domainData"
import type { Account, Report, ReuseGroup, ReportAccount } from "./api"

const ra = (o: Partial<ReportAccount>): ReportAccount => ({
  username: "u", domain: "A", cracked: true, risk_level: "Low", risk_score: 1,
  hibp_breach_count: 0, shared_with: 0, ...o,
})
const grp = (o: Partial<ReuseGroup>): ReuseGroup => ({
  group_id: 1, size: 2, cracked: true, hibp_breach_count: 0, has_da_pathway: false,
  domains: 1, members: [], ...o,
})
const acct = (o: Partial<Account>): Account => ({
  username: "u", domain: "A", cracked: true, password_length: 6, risk_level: "Low",
  risk_score: 1, risk_vector: "", hibp_breached: false, hibp_breach_count: 0,
  da_domains: "None", controlled_object_count: 0, shared_with: 0, enabled: true,
  meets_policy: true, complexity: "ok", ...o,
})
const report = (o: Partial<Report>): Report => ({
  total_accounts: 0, cracked_count: 0, uncracked_count: 0, da_pathways: [], cracked: [],
  cracked_reuse: [], uncracked_reuse: [], hibp_exposed: [], weak_passwords: [],
  violation_counts: { common: 0, dictionary: 0, forbidden: 0, keyboard: 0 }, ...o,
})

describe("domainData", () => {
  it("reuse clusters include only groups touching the domain, sorted by size", () => {
    const rep = report({
      cracked_reuse: [
        grp({ group_id: 1, size: 5, members: [ra({ domain: "A" }), ra({ domain: "B" })] }),
        grp({ group_id: 2, size: 9, members: [ra({ domain: "B" })] }),
        grp({ group_id: 3, size: 3, members: [ra({ domain: "A" })] }),
      ],
    })
    const { cracked } = domainReuseClusters(rep, "A")
    expect(cracked.map((g) => g.group_id)).toEqual([1, 3])
  })
  it("DA paths filter to the domain, sorted by risk", () => {
    const rep = report({ da_pathways: [ra({ domain: "A", username: "x", risk_score: 2 }), ra({ domain: "B" }), ra({ domain: "A", username: "y", risk_score: 9 })] })
    expect(domainDAPaths(rep, "A").map((a) => a.username)).toEqual(["y", "x"])
  })
  it("quick wins = top-N cracked by risk", () => {
    const accts = [acct({ username: "a", risk_score: 3 }), acct({ username: "b", risk_score: 8 }), acct({ username: "c", cracked: false, risk_score: 99 })]
    expect(domainQuickWins(accts, 10).map((a) => a.username)).toEqual(["b", "a"])
  })
  it("policy + wordlist counts", () => {
    const accts = [
      acct({ cracked: true, meets_policy: false, is_common: true }),
      acct({ cracked: true, meets_policy: true, keyboard_pattern_count: 2 }),
      acct({ cracked: false, enabled: false }),
    ]
    expect(domainPolicy(accts)).toEqual({ meets: 1, fails: 1, disabled: 1 })
    expect(domainWordlist(accts)).toEqual({ common: 1, dictionary: 0, banned: 0, keyboard: 1 })
  })
})
