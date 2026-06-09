// Pure functions that derive chart/scorecard data from the redacted account set.
// All inputs come from /api/accounts (no cleartext) so everything is safe to chart.
import type { Account } from "./api"
import { hasDA } from "./util"

export type Rating = "Strong" | "Fair" | "Weak" | "No Data"

export interface Posture {
  score: number
  rating: Rating
  breakdown: { risk: number; strength: number; privilege: number; compliance: number }
  likelihood: "Very High" | "High" | "Medium" | "Low" | "—"
}

const r1 = (n: number) => Math.round(n * 10) / 10

// posture reproduces the legacy executive Security Posture Score:
//   risk distribution (40) + password strength (30) + privilege (15) + compliance (15)
export function posture(accts: Account[]): Posture {
  const total = accts.length
  if (!total) return { score: 0, rating: "No Data", breakdown: { risk: 0, strength: 0, privilege: 0, compliance: 0 }, likelihood: "—" }

  let crit = 0, high = 0, med = 0, cracked = 0, uncracked = 0, da = 0, violations = 0
  for (const a of accts) {
    if (a.risk_level === "Critical") crit++
    else if (a.risk_level === "High") high++
    else if (a.risk_level === "Medium") med++
    if (a.cracked) cracked++
    else uncracked++
    if (hasDA(a.da_domains)) da++
    if (a.cracked && !a.meets_policy) violations++
  }

  let risk = Math.max(0, 100 - (crit / total) * 200 - (high / total) * 150 - (med / total) * 50)
  risk = (risk / 100) * 40
  const strength = cracked + uncracked > 0 ? (uncracked / (cracked + uncracked)) * 30 : 0
  const privilege = Math.max(0, 15 - (da / total) * 100)
  const compliance = ((total - violations) / total) * 15

  const score = r1(risk + strength + privilege + compliance)
  const rating: Rating = score >= 85 ? "Strong" : score >= 70 ? "Fair" : "Weak"

  // Breach-likelihood estimate (legacy estimate_breach_impact tiers)
  let likelihood: Posture["likelihood"] = "Low"
  if (crit > 50 || da > 20) likelihood = "Very High"
  else if (crit > 20 || da > 10) likelihood = "High"
  else if (crit > 5 || da > 3) likelihood = "Medium"

  return {
    score,
    rating,
    breakdown: { risk: r1(risk), strength: r1(strength), privilege: r1(privilege), compliance: r1(compliance) },
    likelihood,
  }
}

export interface Slice {
  name: string
  value: number
  color: string
}

const RISK_HEX: Record<string, string> = { Critical: "#fb7185", High: "#fbbf24", Medium: "#a3e635", Low: "#22d3ee" }

export function riskDistribution(accts: Account[]): Slice[] {
  const order = ["Critical", "High", "Medium", "Low"]
  const counts: Record<string, number> = {}
  for (const a of accts) if (a.risk_level) counts[a.risk_level] = (counts[a.risk_level] || 0) + 1
  return order.filter((r) => counts[r]).map((r) => ({ name: r, value: counts[r], color: RISK_HEX[r] || "#818cf8" }))
}

export function hibpSplit(accts: Account[]): Slice[] {
  let breached = 0
  for (const a of accts) if (a.hibp_breached) breached++
  return [
    { name: "Breached", value: breached, color: "#fb7185" },
    { name: "Not in HIBP", value: accts.length - breached, color: "#22d3ee" },
  ].filter((s) => s.value > 0)
}

export interface Bar {
  name: string
  value: number
}

// Password length buckets (cracked accounts only — uncracked have no length).
export function lengthBuckets(accts: Account[]): Bar[] {
  const labels = ["1–7", "8–9", "10–11", "12–13", "14–15", "16+"]
  const counts = [0, 0, 0, 0, 0, 0]
  for (const a of accts) {
    if (!a.cracked) continue
    const n = a.password_length
    if (n <= 7) counts[0]++
    else if (n <= 9) counts[1]++
    else if (n <= 11) counts[2]++
    else if (n <= 13) counts[3]++
    else if (n <= 15) counts[4]++
    else counts[5]++
  }
  return labels.map((name, i) => ({ name, value: counts[i] }))
}

// Risk-score buckets (0–10 in twos) across all accounts.
export function scoreBuckets(accts: Account[]): Bar[] {
  const labels = ["0–2", "2–4", "4–6", "6–8", "8–10"]
  const counts = [0, 0, 0, 0, 0]
  for (const a of accts) {
    const s = a.risk_score
    const i = s >= 8 ? 4 : s >= 6 ? 3 : s >= 4 ? 2 : s >= 2 ? 1 : 0
    counts[i]++
  }
  return labels.map((name, i) => ({ name, value: counts[i] }))
}

export interface Series {
  name: string
  color: string
  points: { x: number; y: number }[]
}

// HIBP breach count (log10) vs risk score, one series per risk level.
export function hibpVsRisk(accts: Account[]): Series[] {
  const levels: [string, string][] = [
    ["Critical", "#fb7185"],
    ["High", "#fbbf24"],
    ["Medium", "#a3e635"],
    ["Low", "#22d3ee"],
  ]
  return levels
    .map(([name, color]) => ({
      name,
      color,
      points: accts
        .filter((a) => a.risk_level === name)
        .map((a) => ({ x: Math.log10((a.hibp_breach_count || 0) + 1), y: a.risk_score })),
    }))
    .filter((s) => s.points.length > 0)
}

// Distribution of how many other accounts each account shares a secret with.
export function sharingDistribution(accts: Account[]): Bar[] {
  const labels = ["0", "1", "2", "3–5", "6+"]
  const c = [0, 0, 0, 0, 0]
  for (const a of accts) {
    const n = a.shared_with
    if (n <= 0) c[0]++
    else if (n === 1) c[1]++
    else if (n === 2) c[2]++
    else if (n <= 5) c[3]++
    else c[4]++
  }
  return labels.map((name, i) => ({ name, value: c[i] }))
}

// Count of accounts with a Domain Admin pathway, per domain (desc).
export function daExposureByDomain(accts: Account[]): Bar[] {
  const m: Record<string, number> = {}
  for (const a of accts) if (hasDA(a.da_domains)) m[a.domain] = (m[a.domain] || 0) + 1
  return Object.entries(m)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
}

// Count of cracked accounts per complexity class (desc).
export function complexityCounts(accts: Account[]): Bar[] {
  const m: Record<string, number> = {}
  for (const a of accts) if (a.cracked && a.complexity) m[a.complexity] = (m[a.complexity] || 0) + 1
  return Object.entries(m)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
}
