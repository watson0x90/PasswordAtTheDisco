import { describe, expect, it } from "vitest"
import type { Account, ScoreBreakdown } from "./api"
import { weaknessSubFactors, policyViolationText } from "./drawerFactors"

// Base supplies the non-penalty fields; the four weakness sub-penalties
// (length/complexity/dict/sim) are intentionally LEFT OUT so the base mirrors the
// over-the-wire shape (Go omitempty drops zero penalties -> they arrive undefined).
// Override per-case via `o`.
const bd = (o: Partial<ScoreBreakdown>): ScoreBreakdown => ({
  exposure_score: 0, weakness_score: 0, hibp_floor: 0, cracked_floor: 0, reuse_bump: 0,
  roastable_bump: 0, impact_score: 0, privilege_sub_score: 0, da_component: 0,
  domain_modifier: 0, ...o,
})

describe("weaknessSubFactors", () => {
  it("returns only the non-zero sub-penalties, labeled", () => {
    const got = weaknessSubFactors(bd({ length_penalty: 1.2, complexity_penalty: 0, dict_penalty: 3, sim_penalty: 0 }))
    expect(got).toEqual([["Length", 1.2], ["Dictionary", 3]])
  })
  it("returns [] when no breakdown / all zero", () => {
    expect(weaknessSubFactors(undefined)).toEqual([])
    expect(weaknessSubFactors(bd({}))).toEqual([])
  })
})

describe("policyViolationText", () => {
  it("joins the failed rules when policy not met", () => {
    const a = { meets_policy: false, policy_violations: ["No uppercase", "Length < 14"] } as Account
    expect(policyViolationText(a)).toBe("No — No uppercase · Length < 14")
  })
  it("plain No when no detail; Yes when met", () => {
    expect(policyViolationText({ meets_policy: false } as Account)).toBe("No")
    expect(policyViolationText({ meets_policy: true } as Account)).toBe("Yes")
  })
})
