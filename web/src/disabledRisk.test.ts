import { describe, it, expect } from "vitest"
import { disabledLatentRisk } from "./disabledRisk"
import type { Account } from "./api"

// Minimal Account factory: only the fields the predicate reads matter; cast the rest.
function acct(p: Partial<Account>): Account {
  return {
    enabled: true,
    controls_tier0: false,
    da_domains: "None",
    controlled_object_count: 0,
    shared_with: 0,
    ...p,
  } as Account
}

describe("disabledLatentRisk", () => {
  it("false when the account is enabled, regardless of risk signals", () => {
    expect(disabledLatentRisk(acct({ enabled: true, controls_tier0: true }))).toBe(false)
  })
  it("false when disabled but no risk signals", () => {
    expect(disabledLatentRisk(acct({ enabled: false }))).toBe(false)
  })
  it("true when disabled + controls Tier-0", () => {
    expect(disabledLatentRisk(acct({ enabled: false, controls_tier0: true }))).toBe(true)
  })
  it("true when disabled + DA pathway", () => {
    expect(disabledLatentRisk(acct({ enabled: false, da_domains: "CORP.LOCAL" }))).toBe(true)
  })
  it("true when disabled + controlled objects", () => {
    expect(disabledLatentRisk(acct({ enabled: false, controlled_object_count: 3 }))).toBe(true)
  })
  it("true when disabled + reused hash (shared_with >= 2)", () => {
    expect(disabledLatentRisk(acct({ enabled: false, shared_with: 2 }))).toBe(true)
  })
  it("false when disabled + shared_with == 1 (below the raised threshold)", () => {
    expect(disabledLatentRisk(acct({ enabled: false, shared_with: 1 }))).toBe(false)
  })
  it("nil-safe: undefined da_domains does not trip the predicate", () => {
    expect(disabledLatentRisk(acct({ enabled: false, da_domains: undefined as unknown as string }))).toBe(false)
  })
  it("nil-safe: undefined controls_tier0 does not trip the predicate", () => {
    expect(disabledLatentRisk(acct({ enabled: false, controls_tier0: undefined }))).toBe(false)
  })
  it("true when disabled + all risk signals present", () => {
    expect(
      disabledLatentRisk(
        acct({ enabled: false, controls_tier0: true, da_domains: "CORP.LOCAL", controlled_object_count: 5, shared_with: 3 }),
      ),
    ).toBe(true)
  })
})
