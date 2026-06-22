import type { Account, ScoreBreakdown } from "./api"

// weaknessSubFactors decomposes the Exposure "Weakness" bar into its persisted sub-penalties,
// returning only the non-zero ones (omitempty zeros are not informative).
export function weaknessSubFactors(bd: ScoreBreakdown | undefined): [string, number][] {
  if (!bd) return []
  const rows: [string, keyof ScoreBreakdown][] = [
    ["Length", "length_penalty"],
    ["Complexity", "complexity_penalty"],
    ["Dictionary", "dict_penalty"],
    ["Similarity", "sim_penalty"],
  ]
  const out: [string, number][] = []
  for (const [label, key] of rows) {
    const x = bd[key]
    if (typeof x === "number" && x > 0) out.push([label, x])
  }
  return out
}

// policyViolationText renders the "Meets policy" value: "Yes", "No", or "No — <rules>".
export function policyViolationText(a: Account): string {
  if (a.meets_policy) return "Yes"
  const v = a.policy_violations
  return v && v.length ? `No — ${v.join(" · ")}` : "No"
}
