import { describe, it, expect } from "vitest"
import { priorityWorklist } from "./worklist"
import type { Account } from "./api"
const acct = (o: Partial<Account>): Account => ({
  username: "u", domain: "D", cracked: false, hibp_breached: false, hibp_breach_count: 0,
  shared_with: 0, da_domains: "None", escalated_by_shared_da: false, pwd_never_expires: false,
  risk_score: 0, risk_level: "Low", enabled: true,
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
