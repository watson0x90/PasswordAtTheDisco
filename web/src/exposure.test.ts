import { describe, it, expect } from "vitest"
import { exposureHeadline, crossDomainBridges, hibpTriage, blastRadius } from "./exposure"
import type { Account, Report, ReportAccount, ReuseGroup } from "./api"

const acct = (o: Partial<Account>): Account => ({
  username: "u", domain: "A", cracked: false, password_length: 0, risk_level: "Low",
  risk_score: 0, risk_vector: "", hibp_breached: false, hibp_breach_count: 0,
  da_domains: "None", controlled_object_count: 0, shared_with: 0, enabled: true,
  meets_policy: true, complexity: "", ...o,
})
const ra = (o: Partial<ReportAccount>): ReportAccount => ({
  username: "u", domain: "A", cracked: false, risk_level: "Low", risk_score: 0,
  hibp_breach_count: 0, shared_with: 0, ...o,
})
const grp = (o: Partial<ReuseGroup>): ReuseGroup => ({
  group_id: 1, size: 2, cracked: false, hibp_breach_count: 0, has_da_pathway: false,
  domains: 1, members: [], ...o,
})
const report = (o: Partial<Report>): Report => ({
  total_accounts: 0, cracked_count: 0, uncracked_count: 0, da_pathways: [], cracked: [],
  cracked_reuse: [], uncracked_reuse: [], hibp_exposed: [], weak_passwords: [],
  violation_counts: { common: 0, dictionary: 0, forbidden: 0, keyboard: 0 }, ...o,
})

describe("exposureHeadline", () => {
  it("counts cracked∩DA, cracked∩HIBP, cross-domain groups + domains spanned", () => {
    const accts = [
      acct({ cracked: true, da_domains: "CORP" }),
      acct({ cracked: true, hibp_breached: true }),
      acct({ cracked: true, da_domains: "CORP", hibp_breached: true }),
      acct({ cracked: false, da_domains: "CORP" }),
    ]
    const rep = report({
      cracked_reuse: [grp({ members: [ra({ domain: "A" }), ra({ domain: "B" })] })],
      uncracked_reuse: [grp({ members: [ra({ domain: "B" }), ra({ domain: "C" })] })],
    })
    const h = exposureHeadline(accts, rep)
    expect(h.crackedDA).toBe(2)
    expect(h.crackedHibp).toBe(2)
    expect(h.crossDomainGroups).toBe(2)
    expect(h.domainsSpanned).toBe(3)
  })
})

describe("crossDomainBridges", () => {
  it("matrix counts clusters per domain pair; single-domain groups excluded", () => {
    const rep = report({
      cracked_reuse: [
        grp({ group_id: 1, size: 5, has_da_pathway: true, members: [ra({ domain: "CORP" }), ra({ domain: "DMZ" })] }),
        grp({ group_id: 2, size: 9, members: [ra({ domain: "CORP" })] }),
      ],
      uncracked_reuse: [grp({ group_id: 3, size: 3, members: [ra({ domain: "CORP" }), ra({ domain: "DMZ" })] })],
    })
    const { matrix, clusters, domains } = crossDomainBridges(rep)
    expect(matrix["CORP"]["DMZ"]).toBe(2)
    expect(clusters.length).toBe(2)
    expect(clusters[0].hasDA).toBe(true)
    expect(domains).toEqual(["CORP", "DMZ"])
  })
})

describe("hibpTriage", () => {
  it("splits cracked vs not, sorted by breach count desc", () => {
    const rep = report({
      hibp_exposed: [
        ra({ username: "a", cracked: true, hibp_breach_count: 10 }),
        ra({ username: "b", cracked: true, hibp_breach_count: 99 }),
        ra({ username: "c", cracked: false, hibp_breach_count: 5 }),
      ],
    })
    const { tier1, tier2 } = hibpTriage(rep)
    expect(tier1.map((a) => a.username)).toEqual(["b", "a"])
    expect(tier2.map((a) => a.username)).toEqual(["c"])
  })
})

describe("blastRadius", () => {
  it("scores priority, builds reasons, includes+marks disabled, sorts desc", () => {
    const rows = blastRadius([
      acct({ username: "low", cracked: false }),
      acct({ username: "mid", cracked: true, shared_with: 3 }),
      acct({ username: "top", cracked: true, da_domains: "CORP", hibp_breached: true, hibp_breach_count: 40 }),
      acct({ username: "dis", cracked: true, enabled: false }),
    ])
    expect(rows.map((r) => r.account.username)).toEqual(["top", "mid", "dis"])
    expect(rows[0].reasons).toContain("DA")
    expect(rows[0].reasons).toContain("HIBP 40")
    expect(rows.find((r) => r.account.username === "dis")!.reasons).toContain("disabled")
  })
})
