// Go⇄TS posture parity golden test.
// Loads the SAME fixture as internal/model TestPostureGolden (Go) and asserts
// that posture() produces identical output for each case. Any divergence between
// the Go formula and the TS mirror fails here — that is the whole point.
import { describe, it, expect } from "vitest"
import type { Account } from "./api"
import { posture } from "./insights"
import fixture from "./__fixtures__/posture_golden.json"

interface GoldenAccount {
  enabled: boolean
  cracked: boolean
  risk_level: string
  meets_policy: boolean
  da_domains: string
  controls_tier0: boolean
  escalated_by_shared_da: boolean
  escalated_by_mass_reuse: boolean
  impact_known: boolean
}

interface GoldenExpect {
  score: number
  rating: string
  reachability: string
  reachability_pct: string
  overall: number
  verdict: string
  verdict_reason: string
  likelihood: string
}

interface GoldenCase {
  name: string
  accounts: GoldenAccount[]
  expect: GoldenExpect
}

const cases = fixture as GoldenCase[]

function toAccount(ga: GoldenAccount): Account {
  return {
    username: "u",
    domain: "D",
    cracked: ga.cracked,
    password_length: 0,
    risk_level: ga.risk_level,
    risk_score: 0,
    risk_vector: "",
    hibp_breached: false,
    hibp_breach_count: 0,
    da_domains: ga.da_domains,
    controlled_object_count: 0,
    shared_with: 0,
    enabled: ga.enabled,
    meets_policy: ga.meets_policy,
    complexity: "",
    exposure_score: 0,
    impact_score: null,
    impact_known: ga.impact_known,
    percentile: 0,
    controls_tier0: ga.controls_tier0,
    escalated_by_shared_da: ga.escalated_by_shared_da,
    escalated_by_mass_reuse: ga.escalated_by_mass_reuse,
  }
}

describe("posture golden (Go⇄TS parity — same fixture as TestPostureGolden)", () => {
  for (const c of cases) {
    it(c.name, () => {
      const accts = c.accounts.map(toAccount)
      const p = posture(accts)
      const e = c.expect
      expect(p.score).toBe(e.score)
      expect(p.rating).toBe(e.rating)
      expect(p.reachability).toBe(e.reachability)
      expect(p.reachability_pct).toBe(e.reachability_pct)
      expect(p.overall).toBe(e.overall)
      expect(p.verdict).toBe(e.verdict)
      expect(p.verdict_reason ?? "").toBe(e.verdict_reason)
      expect(p.likelihood).toBe(e.likelihood)
    })
  }
})
