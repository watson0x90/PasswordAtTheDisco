import { describe, expect, it } from "vitest"
import { credentialObtainable, hasDA, hasObtainableDA } from "./util"

describe("hasDA", () => {
  it("returns true for a real domain string", () => {
    expect(hasDA("CORP.LOCAL")).toBe(true)
  })
  it("returns false for empty string", () => {
    expect(hasDA("")).toBe(false)
  })
  it("returns false for None", () => {
    expect(hasDA("None")).toBe(false)
  })
  it("returns false for Unknown", () => {
    expect(hasDA("Unknown")).toBe(false)
  })
})

// credentialObtainable mirrors Go model.CredentialObtainable (no enabled gate).
describe("credentialObtainable", () => {
  it("cracked => true", () => {
    expect(credentialObtainable({ cracked: true, hibp_breached: false })).toBe(true)
  })
  it("hibp_breached => true", () => {
    expect(credentialObtainable({ cracked: false, hibp_breached: true })).toBe(true)
  })
  it("escalated_by_shared_da => true", () => {
    expect(credentialObtainable({ cracked: false, hibp_breached: false, escalated_by_shared_da: true })).toBe(true)
  })
  it("escalated_by_mass_reuse => true", () => {
    expect(credentialObtainable({ cracked: false, hibp_breached: false, escalated_by_mass_reuse: true })).toBe(true)
  })
  it("none of the signals => false", () => {
    expect(credentialObtainable({ cracked: false, hibp_breached: false })).toBe(false)
  })
  it("all signals false (explicit) => false", () => {
    expect(credentialObtainable({ cracked: false, hibp_breached: false, escalated_by_shared_da: false, escalated_by_mass_reuse: false })).toBe(false)
  })
})

// hasObtainableDA mirrors Go Account.HasObtainableDAPathway = HasDAPathway && CredentialObtainable.
describe("hasObtainableDA", () => {
  const base = { cracked: false, hibp_breached: false }

  it("cracked + real DA domain => true", () => {
    expect(hasObtainableDA({ ...base, cracked: true, da_domains: "CORP.LOCAL" })).toBe(true)
  })
  it("hibp_breached + real DA domain => true", () => {
    expect(hasObtainableDA({ ...base, hibp_breached: true, da_domains: "CORP.LOCAL" })).toBe(true)
  })
  it("escalated_by_shared_da + real DA domain => true", () => {
    expect(hasObtainableDA({ ...base, escalated_by_shared_da: true, da_domains: "CORP.LOCAL" })).toBe(true)
  })
  it("escalated_by_mass_reuse + real DA domain => true", () => {
    expect(hasObtainableDA({ ...base, escalated_by_mass_reuse: true, da_domains: "CORP.LOCAL" })).toBe(true)
  })
  it("DA domain but no obtainable signal => FALSE (the key correctness case)", () => {
    expect(hasObtainableDA({ ...base, da_domains: "CORP.LOCAL" })).toBe(false)
  })
  it("no DA path at all => false", () => {
    expect(hasObtainableDA({ ...base, cracked: true, da_domains: "None" })).toBe(false)
  })
  it("no DA path (empty string) + cracked => false", () => {
    expect(hasObtainableDA({ ...base, cracked: true, da_domains: "" })).toBe(false)
  })
  it("no DA path (Unknown) + cracked => false", () => {
    expect(hasObtainableDA({ ...base, cracked: true, da_domains: "Unknown" })).toBe(false)
  })
})
