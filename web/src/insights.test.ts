import { describe, it, expect } from "vitest"
import type { Account } from "./api"
import { posture, riskDistribution, hibpSplit, complexityLabel, similarityNetwork, axisFactorBars } from "./insights"

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

describe("posture (parity with Go model.PostureScore golden)", () => {
  // Same fixture + expectations as internal/model TestPostureScoreGolden, so a
  // one-sided tweak to either implementation fails CI.
  it("matches the Go golden: 22.5 Weak, breakdown {0,0,15,7.5}", () => {
    const p = posture([
      acct({ risk_level: "Critical", cracked: true, hibp_breached: true, meets_policy: false }),
      acct({ risk_level: "Low", cracked: true, meets_policy: true }),
    ])
    expect(p.score).toBe(22.5)
    expect(p.rating).toBe("Weak")
    expect(p.breakdown).toEqual({ risk: 0, strength: 0, privilege: 15, compliance: 7.5 })
  })

  // Second golden (mirrors the Go TestPostureScoreGolden second case) with NON-ZERO
  // risk + strength, so a one-sided coefficient drift can't slip through.
  it("matches the Go golden (non-zero risk+strength): 57 Weak, {12,18,15,12}", () => {
    const p = posture([
      acct({ risk_level: "Critical", cracked: true, meets_policy: false }),
      acct({ risk_level: "High", cracked: true, meets_policy: true }),
      acct({ risk_level: "Low", cracked: false }),
      acct({ risk_level: "Low", cracked: false }),
      acct({ risk_level: "Low", cracked: false }),
    ])
    expect(p.score).toBe(57)
    expect(p.rating).toBe("Weak")
    expect(p.breakdown).toEqual({ risk: 12, strength: 18, privilege: 15, compliance: 12 })
  })

  it("empty set -> No Data", () => {
    const p = posture([])
    expect(p.score).toBe(0)
    expect(p.rating).toBe("No Data")
  })

  it("all-uncracked, no risk, compliant -> Strong", () => {
    const p = posture([acct({ cracked: false, risk_level: "Low" }), acct({ cracked: false, risk_level: "Low" })])
    expect(p.rating).toBe("Strong")
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
