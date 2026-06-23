import { describe, expect, it } from "vitest"
import type { Account } from "./api"
import { selectedAccount } from "./selectedAccount"

function acct(username: string, domain: string, risk_vector: string): Account {
  // Only the fields the test asserts on matter; cast the partial through unknown.
  return { username, domain, risk_vector } as unknown as Account
}

describe("selectedAccount", () => {
  it("returns null when nothing is captured", () => {
    expect(selectedAccount([], null)).toBeNull()
    expect(selectedAccount(null, null)).toBeNull()
  })

  it("returns the LIVE row (fresh risk_vector) when the key matches", () => {
    const captured = acct("alice", "CORP", "OLD")
    const live = acct("alice", "CORP", "NEW")
    const result = selectedAccount([live], captured)
    expect(result).toBe(live)
    expect(result?.risk_vector).toBe("NEW")
  })

  it("matches on BOTH username and domain", () => {
    const captured = acct("alice", "CORP", "OLD")
    const wrongDomain = acct("alice", "OTHER", "NEW")
    // No live match -> falls back to captured, not the same-username other-domain row.
    expect(selectedAccount([wrongDomain], captured)).toBe(captured)
  })

  it("falls back to the captured object when the account is absent (e.g. Compare cross-audit)", () => {
    const captured = acct("ghost", "CORP", "OLD")
    expect(selectedAccount([acct("alice", "CORP", "NEW")], captured)).toBe(captured)
    expect(selectedAccount(null, captured)).toBe(captured)
    expect(selectedAccount([], captured)).toBe(captured)
  })
})
