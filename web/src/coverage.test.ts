import { describe, it, expect } from "vitest"
import type { Account } from "./api"
import { unenrichedAccounts, coverageWhy, coverageCsv } from "./coverage"

const a = (p: Partial<Account>): Account => ({
  username: "u", domain: "CORP", cracked: false, risk_level: "Low", exposure_score: 0,
  impact_score: null, impact_known: false, da_domains: "None", hibp_breached: false,
  ...p,
} as Account)

describe("unenrichedAccounts", () => {
  it("selects exactly the Impact-Unknown (isProvisional) accounts", () => {
    const accts = [a({ username: "x", impact_known: false, impact_score: null }), a({ username: "y", impact_known: true, impact_score: 5 })]
    expect(unenrichedAccounts(accts).map((x) => x.username)).toEqual(["x"])
  })
})

describe("coverageWhy", () => {
  it("all enriched", () => {
    expect(coverageWhy({ unenrichedCount: 0, totalCount: 10, enrichRan: true }).kind).toBe("all-covered")
  })
  it("never run", () => {
    expect(coverageWhy({ unenrichedCount: 4, totalCount: 10, enrichRan: false }).kind).toBe("never-run")
  })
  it("ran but unmatched", () => {
    expect(coverageWhy({ unenrichedCount: 4, totalCount: 10, enrichRan: true }).kind).toBe("ran-unmatched")
  })
})

describe("coverageCsv", () => {
  it("emits a header + one row per account with NO secret fields", () => {
    const csv = coverageCsv([a({ username: "svc", domain: "CORP", cracked: true, risk_level: "High" })] as Account[])
    const lines = csv.trim().split("\n")
    expect(lines[0]).toBe("Username,Domain,Cracked,Exposure level")
    expect(lines[1]).toBe("svc,CORP,yes,High")
    expect(csv).not.toMatch(/password|nthash|hash/i)
  })
  it("escapes commas/quotes in fields", () => {
    const csv = coverageCsv([a({ username: 'a,b"c', domain: "CORP", risk_level: "Low" })] as Account[])
    expect(csv.split("\n")[1]).toContain('"a,b""c"')
  })
})
