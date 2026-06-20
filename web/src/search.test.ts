import { describe, it, expect } from "vitest"
import { filterAccounts } from "./search"
import type { Account } from "./api"

const acct = (username: string, domain: string): Account =>
  ({ username, domain } as Account)

const data: Account[] = [
  acct("administrator", "PHANTOM.CORP"),
  acct("alice", "GHOST.CORP"),
  acct("bob", "PHANTOM.CORP"),
]

describe("filterAccounts", () => {
  it("returns [] for an empty query", () => {
    expect(filterAccounts(data, "")).toEqual([])
    expect(filterAccounts(data, "   ")).toEqual([])
  })
  it("matches username case-insensitively", () => {
    expect(filterAccounts(data, "ADMIN").map((a) => a.username)).toEqual(["administrator"])
  })
  it("matches domain", () => {
    expect(filterAccounts(data, "phantom").map((a) => a.username)).toEqual(["administrator", "bob"])
  })
  it("respects the cap", () => {
    expect(filterAccounts(data, "corp", 1)).toHaveLength(1)
  })
})
