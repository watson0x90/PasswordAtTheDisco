import { describe, it, expect, test } from "vitest"
import type { Account, Report, ReuseGroup } from "./api"
import { posture, riskDistribution, hibpSplit, complexityLabel, similarityNetwork, axisFactorBars, crossDomainReuseGraph, isReachable, topControllers } from "./insights"

function acct(p: Partial<Account>): Account {
  return {
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
    percentile: 0,
    ...p,
  }
}

describe("posture (parity with Go model.PostureScore golden — Hygiene×Reachability formula)", () => {
  // Same fixture + expectations as internal/model TestPostureScoreGolden, so a
  // one-sided tweak to either implementation fails CI.
  // Weights: risk=45, strength=35, compliance=20 (privilege term removed).
  // 2 enabled accounts: 1 Critical cracked non-compliant, 1 Low cracked compliant.
  // active=2: risk=max(0,100-1/2*200)/100*45=0; strength=0/2*35=0; compliance=(2-1)/2*20=10 -> 10.0 Weak
  it("matches the Go golden: 10.0 Weak, breakdown {0,0,0,10}", () => {
    const p = posture([
      acct({ risk_level: "Critical", cracked: true, hibp_breached: true, meets_policy: false }),
      acct({ risk_level: "Low", cracked: true, meets_policy: true }),
    ])
    expect(p.score).toBe(10.0)
    expect(p.rating).toBe("Weak")
    expect(p.breakdown).toEqual({ risk: 0, strength: 0, privilege: 0, compliance: 10.0 })
  })

  // Second golden (mirrors the Go TestPostureScoreGolden second case) with NON-ZERO
  // risk + strength, so a one-sided coefficient drift can't slip through.
  // active=5: risk=max(0,100-1/5*200-1/5*150)/100*45=13.5; strength=3/5*35=21; compliance=(5-1)/5*20=16 -> 50.5 Weak
  it("matches the Go golden (non-zero risk+strength): 50.5 Weak, {13.5,21,0,16}", () => {
    const p = posture([
      acct({ risk_level: "Critical", cracked: true, meets_policy: false }),
      acct({ risk_level: "High", cracked: true, meets_policy: true }),
      acct({ risk_level: "Low", cracked: false }),
      acct({ risk_level: "Low", cracked: false }),
      acct({ risk_level: "Low", cracked: false }),
    ])
    expect(p.score).toBe(50.5)
    expect(p.rating).toBe("Weak")
    expect(p.breakdown).toEqual({ risk: 13.5, strength: 21.0, privilege: 0, compliance: 16.0 })
  })

  it("empty set -> No Data", () => {
    const p = posture([])
    expect(p.score).toBe(0)
    expect(p.rating).toBe("No Data")
    expect(p.verdict).toBe("No Data")
  })

  it("all-uncracked, no risk, compliant -> Strong + Sound verdict", () => {
    const p = posture([acct({ cracked: false, risk_level: "Low" }), acct({ cracked: false, risk_level: "Low" })])
    expect(p.rating).toBe("Strong")
    expect(p.verdict).toBe("Sound")
  })

  it("disabled accounts excluded from hygiene (enabled=false padding does not inflate score)", () => {
    const enabled = [
      acct({ enabled: true, risk_level: "Low", cracked: true, meets_policy: false }),
      acct({ enabled: true, risk_level: "Low", cracked: false, meets_policy: true }),
    ]
    // 8 disabled Critical accounts must not affect the hygiene score
    const disabled = Array.from({ length: 8 }, () =>
      acct({ enabled: false, risk_level: "Critical", cracked: true, meets_policy: false })
    )
    const p = posture([...enabled, ...disabled])
    // active=2: risk=45, strength=17.5, compliance=10 -> 72.5 Fair
    expect(p.score).toBeGreaterThan(72.0)
    expect(p.score).toBeLessThan(73.0)
    expect(p.breakdown.privilege).toBe(0)
  })

  it("privilege breakdown is always 0 (term removed)", () => {
    const p = posture([acct({ risk_level: "Critical", cracked: true })])
    expect(p.breakdown.privilege).toBe(0)
  })
})

describe("distributions", () => {
  it("riskDistribution counts by level", () => {
    const d = riskDistribution([acct({ risk_level: "Critical" }), acct({ risk_level: "Critical" }), acct({ risk_level: "Low" })])
    const crit = d.find((x) => x.name === "Critical")
    expect(crit?.value).toBe(2)
  })

  it("hibpSplit separates breached from clean", () => {
    const d = hibpSplit([acct({ hibp_breached: true }), acct({ hibp_breached: false }), acct({ hibp_breached: false })])
    const breached = d.find((x) => /breach/i.test(x.name))
    expect(breached?.value).toBe(1)
  })
})

describe("complexityLabel", () => {
  it("maps the full-class key to class tokens", () => {
    expect(complexityLabel("mixedalphaspecialnum")).toBe("a–z A–Z 0–9 !@#")
  })
  it("maps a partial key", () => {
    expect(complexityLabel("loweralphanum")).toBe("a–z 0–9")
  })
  it("passes through unknown keys unchanged", () => {
    expect(complexityLabel("weird")).toBe("weird")
  })
})

const sa = (username: string, domain: string, score: number, peers: { username: string; domain: string; score: number }[]): Account =>
  ({ username, domain, cracked: true, similarity_score: score, risk_level: "High", similar_peers: peers } as Account)

describe("similarityNetwork edges", () => {
  it("builds deduped edges only between nodes, from similar_peers", () => {
    const accts: Account[] = [
      sa("alice", "CORP", 0.9, [{ username: "bob", domain: "CORP", score: 0.9 }]),
      sa("bob", "CORP", 0.9, [{ username: "alice", domain: "CORP", score: 0.9 }]),
      sa("carol", "CORP", 0.8, [{ username: "ghost", domain: "OTHER", score: 0.85 }]),
    ]
    const { nodes, edges } = similarityNetwork(accts)
    expect(nodes.length).toBe(3)
    expect(edges.length).toBe(1)
    expect(edges[0].weight).toBe(3)
    expect(edges[0].label).toBe("90%")
  })
})

// bdAcct builds on the real acct(...) factory (Partial<Account> -> Account); it sets
// the v2 axis fields + a partial v2 score_breakdown so axisFactorBars has sub-scores
// to average. impact_score is null when impactKnown is false (load-bearing Unknown).
const bdAcct = (level: string, impactKnown: boolean, bd: Partial<NonNullable<Account["score_breakdown"]>>): Account =>
  acct({
    risk_level: level,
    impact_known: impactKnown,
    exposure_score: 5,
    impact_score: impactKnown ? 5 : null,
    score_breakdown: bd,
  })

describe("axisFactorBars", () => {
  it("groups Exposure + Impact sub-scores per tier, coalescing missing keys to 0", () => {
    const bars = axisFactorBars([
      bdAcct("Critical", true, { weakness_score: 8, hibp_floor: 4, privilege_sub_score: 7 }),
      bdAcct("Critical", true, { weakness_score: 6, hibp_floor: 4, privilege_sub_score: 9 }),
    ])
    const crit = bars.find((b) => b.tier === "Critical")!
    // averaged within the tier; absent factors (cracked_floor, reuse_bump, ...) are 0
    expect(crit.exposure.find((f) => f.name === "Weakness")!.value).toBe(7) // (8+6)/2
    expect(crit.exposure.find((f) => f.name === "HIBP floor")!.value).toBe(4)
    expect(crit.exposure.find((f) => f.name === "Reuse")!.value).toBe(0) // absent => 0, NOT unknown
    expect(crit.impact.find((f) => f.name === "Privilege")!.value).toBe(8) // (7+9)/2
    expect(crit.impactKnown).toBe(true)
  })

  it("greys the Impact group for a tier with no enriched accounts", () => {
    const bars = axisFactorBars([bdAcct("High", false, { weakness_score: 6 })])
    const high = bars.find((b) => b.tier === "High")!
    expect(high.impactKnown).toBe(false) // no enriched account in this tier
    expect(high.exposure.find((f) => f.name === "Weakness")!.value).toBe(6)
  })

  it("omits empty tiers", () => {
    const bars = axisFactorBars([bdAcct("Critical", true, { weakness_score: 5 })])
    expect(bars.some((b) => b.tier === "Low")).toBe(false)
  })

  it("treats a known-but-null impact as not-enriched (shared predicate, no drift)", () => {
    // A malformed payload the backend should never emit, but the shared impactIsKnown
    // predicate (impact_known AND impact_score !== null) guards it: this must NOT be
    // averaged into the Impact group as an enriched account.
    const bars = axisFactorBars([
      acct({
        risk_level: "High",
        impact_known: true,
        impact_score: null,
        exposure_score: 5,
        score_breakdown: { weakness_score: 6, privilege_sub_score: 9 },
      }),
    ])
    const high = bars.find((b) => b.tier === "High")!
    expect(high.impactKnown).toBe(false)
  })
})

const grp = (size: number, domains: string[], cracked = true): ReuseGroup =>
  ({ group_id: 1, size, cracked, has_da_pathway: false, hibp_breach_count: 0, domains: domains.length, members: domains.map((d, i) => ({ username: `u${i}`, domain: d } as any)) } as ReuseGroup)
const rep = (cracked: ReuseGroup[], uncracked: ReuseGroup[] = []): Report =>
  ({ cracked_reuse: cracked, uncracked_reuse: uncracked } as Report)
const acctD = (domain: string): Account => ({ domain, risk_level: "Low", cracked: true } as Account)

describe("crossDomainReuseGraph (real reuse groups)", () => {
  it("links exactly the domains that co-occur in a reuse group", () => {
    const g = crossDomainReuseGraph(rep([grp(3, ["CORP", "EU"])]), [acctD("CORP"), acctD("EU")])
    expect(g.edges).toHaveLength(1)
    expect(new Set([g.edges[0].source, g.edges[0].target])).toEqual(new Set(["CORP", "EU"]))
    expect(g.nodes.map((n) => n.id).sort()).toEqual(["CORP", "EU"])
  })
  it("emits NO edge for a single-domain group", () => {
    const g = crossDomainReuseGraph(rep([grp(5, ["CORP", "CORP"])]), [acctD("CORP")])
    expect(g.edges).toHaveLength(0)
  })
  it("does NOT fabricate an edge between domains that share no group", () => {
    // CORP and LAB BOTH have shared accounts (shared_with>0) but in SEPARATE single-domain
    // groups -> no real bridge. The old heuristic linked any two domains with shared accounts,
    // so it would fabricate a CORP-LAB edge here; the real-reuse-group version must not.
    const corp = { ...acctD("CORP"), shared_with: 2 } as Account
    const lab = { ...acctD("LAB"), shared_with: 2 } as Account
    const g = crossDomainReuseGraph(rep([grp(4, ["CORP", "CORP"]), grp(4, ["LAB", "LAB"])]), [corp, lab])
    expect(g.edges).toHaveLength(0)
  })
  it("returns empty when report is null", () => {
    expect(crossDomainReuseGraph(null, [acctD("CORP")])).toEqual({ nodes: [], edges: [] })
  })
})

import { kpiCounts } from "./insights"
import type { Summary } from "./api"

describe("kpiCounts", () => {
  const accts = [
    { cracked: true, hibp_breached: true, da_domains: "CORP.LOCAL" },
    { cracked: false, hibp_breached: false, da_domains: "None" },
  ] as Account[]
  it("prefers Summary counts when present", () => {
    const s = { total_accounts: 100, cracked: 40, hibp_breached: 25, da_pathways: 7 } as Summary
    expect(kpiCounts(s, accts)).toEqual({ total: 100, cracked: 40, breached: 25, da: 7 })
  })
  it("falls back to client counts when Summary is null", () => {
    expect(kpiCounts(null, accts)).toEqual({ total: 2, cracked: 1, breached: 1, da: 1 })
  })
})

// Task C1: isReachable + topControllers helpers
test("isReachable: enabled && any obtainable signal", () => {
  expect(isReachable({ enabled: true, cracked: true } as any)).toBe(true)
  expect(isReachable({ enabled: true, hibp_breached: true } as any)).toBe(true)
  expect(isReachable({ enabled: true, escalated_by_shared_da: true } as any)).toBe(true)
  expect(isReachable({ enabled: true, escalated_by_mass_reuse: true } as any)).toBe(true)
  expect(isReachable({ enabled: false, cracked: true } as any)).toBe(false)
  expect(isReachable({ enabled: true } as any)).toBe(false)
  expect(isReachable({ enabled: false } as any)).toBe(false)
})

test("topControllers: filter >0, sort desc, top N + remaining >100 count", () => {
  const a = (n: number, username = `u${n}`) => ({ controlled_object_count: n, username } as any)
  const { rows, moreOver100 } = topControllers([a(0), a(5), a(16778), a(101), a(2542), a(150)], 2)
  expect(rows.map((r: any) => r.controlled_object_count)).toEqual([16778, 2542]) // desc, top 2
  expect(moreOver100).toBe(2) // 101 and 150 are >100 and not in rows; 5 is not >100
})

test("topControllers: stable tie-break by username localeCompare", () => {
  const a = (n: number, username: string) => ({ controlled_object_count: n, username } as any)
  const { rows } = topControllers([a(10, "zebra"), a(10, "alpha"), a(10, "mango")], 3)
  expect(rows.map((r: any) => r.username)).toEqual(["alpha", "mango", "zebra"])
})

test("topControllers: filters out zero-count accounts", () => {
  const a = (n: number) => ({ controlled_object_count: n, username: `u${n}` } as any)
  const { rows } = topControllers([a(0), a(0), a(0)], 5)
  expect(rows).toHaveLength(0)
})

test("topControllers: moreOver100 is 0 when remaining are all <=100", () => {
  const a = (n: number) => ({ controlled_object_count: n, username: `u${n}` } as any)
  const { rows, moreOver100 } = topControllers([a(50), a(40), a(30)], 1)
  expect(rows[0].controlled_object_count).toBe(50)
  expect(moreOver100).toBe(0) // 40 and 30 are not >100
})
