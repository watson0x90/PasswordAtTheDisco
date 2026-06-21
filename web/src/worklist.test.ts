import { describe, it, expect } from "vitest"
import { priorityWorklist, segmentWorklist } from "./worklist"
import type { Account } from "./api"
const acct = (o: Partial<Account>): Account => ({
  username: "u", domain: "D", cracked: false, hibp_breached: false, hibp_breach_count: 0,
  shared_with: 0, da_domains: "None", escalated_by_shared_da: false, pwd_never_expires: false,
  risk_score: 0, risk_level: "Low", enabled: true,
  exposure_score: 0, impact_score: null, impact_known: true,
  ...o,
} as Account)
describe("priorityWorklist", () => {
  it("ranks DA+cracked+HIBP above merely cracked", () => {
    const wl = priorityWorklist([
      acct({ username: "low", cracked: true, risk_score: 5 }),
      acct({ username: "high", cracked: true, hibp_breached: true, hibp_breach_count: 9, da_domains: "CORP", risk_score: 10 }),
    ])
    expect(wl[0].account.username).toBe("high")
    expect(wl[0].reasons).toContain("DA path")
    expect(wl[0].action).toMatch(/Rotate now/)
  })
  it("excludes accounts with no risk signal", () => {
    expect(priorityWorklist([acct({})])).toHaveLength(0)
  })
  it("breaks ties by risk_score", () => {
    const wl = priorityWorklist([
      acct({ username: "a", cracked: true, risk_score: 3 }),
      acct({ username: "b", cracked: true, risk_score: 8 }),
    ])
    expect(wl[0].account.username).toBe("b")
  })
  it("surfaces a never-expires-only account with Enforce expiry, ranked low", () => {
    const wl = priorityWorklist([
      acct({ username: "ne", pwd_never_expires: true }),
      acct({ username: "cr", cracked: true, risk_score: 5 }),
    ])
    const ne = wl.find((w) => w.account.username === "ne")
    expect(ne).toBeTruthy()
    expect(ne!.action).toBe("Enforce expiry")
    expect(wl[0].account.username).toBe("cr") // cracked outranks never-expires-only
  })
  it("recommends rotation for a shared (reused) but uncracked password", () => {
    const [w] = priorityWorklist([acct({ shared_with: 4 })])
    expect(w.action).toBe("Rotate (shared password)")
    expect(w.reasons).toContain("Shared 4")
  })
})

describe("segmentWorklist", () => {
  it("segregates Unknown-impact accounts and orders the rest by Level -> Impact -> Exposure", () => {
    const seg = segmentWorklist([
      acct({ username: "lowexp", risk_level: "High", impact_known: true, impact_score: 6, exposure_score: 4 }),
      acct({ username: "hiexp", risk_level: "High", impact_known: true, impact_score: 6, exposure_score: 7 }),
      acct({ username: "crit", risk_level: "Critical", impact_known: true, impact_score: 9, exposure_score: 9 }),
      acct({ username: "unk", risk_level: "High", impact_known: false, impact_score: null, exposure_score: 8 }),
    ])
    expect(seg.ranked.map((a) => a.username)).toEqual(["crit", "hiexp", "lowexp"])
    expect(seg.needsEnrichment.map((a) => a.username)).toEqual(["unk"])
  })

  it("uses percentile as the final tie-break when present", () => {
    const seg = segmentWorklist([
      acct({ username: "p1", risk_level: "High", impact_known: true, impact_score: 6, exposure_score: 6, percentile: 0.4 }),
      acct({ username: "p2", risk_level: "High", impact_known: true, impact_score: 6, exposure_score: 6, percentile: 0.9 }),
    ])
    expect(seg.ranked[0].username).toBe("p2") // higher percentile first
  })

  it("keeps ties stable (input order) when all sort keys are equal", () => {
    const seg = segmentWorklist([
      acct({ username: "first", risk_level: "High", impact_known: true, impact_score: 6, exposure_score: 6 }),
      acct({ username: "second", risk_level: "High", impact_known: true, impact_score: 6, exposure_score: 6 }),
    ])
    expect(seg.ranked.map((a) => a.username)).toEqual(["first", "second"])
  })

  it("orders provisional (Unknown-impact) accounts only into needsEnrichment, never the ranked list", () => {
    const seg = segmentWorklist([
      acct({ username: "u1", risk_level: "Critical", impact_known: false, impact_score: null, exposure_score: 9 }),
      acct({ username: "k1", risk_level: "Low", impact_known: true, impact_score: 2, exposure_score: 2 }),
    ])
    expect(seg.ranked.map((a) => a.username)).toEqual(["k1"])
    expect(seg.needsEnrichment.map((a) => a.username)).toEqual(["u1"])
  })
})
