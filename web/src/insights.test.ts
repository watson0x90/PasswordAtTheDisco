import { describe, it, expect } from "vitest"
import type { Account } from "./api"
import { posture, riskDistribution, hibpSplit, complexityLabel, similarityNetwork } from "./insights"

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
