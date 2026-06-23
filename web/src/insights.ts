// Pure functions that derive chart/scorecard data from the redacted account set.
// All inputs come from /api/accounts (no cleartext) so everything is safe to chart.
import type { Account, Report, Summary } from "./api"
import { hasDA } from "./util"
import { impactIsKnown } from "./matrix"

export type Rating = "Strong" | "Fair" | "Weak" | "No Data"

export interface Posture {
  score: number
  rating: Rating
  breakdown: { risk: number; strength: number; privilege: number; compliance: number }
  likelihood: "Very High" | "High" | "Medium" | "Low" | "—"
}

const r1 = (n: number) => Math.round(n * 10) / 10

// posture computes the score for an arbitrary account subset (used by the
// per-domain mini-dashboards, which have no server endpoint). The authoritative
// WHOLE-AUDIT posture is served by /api/summary (Go model.PostureScore) and drives
// the Overview, HTML export, and Compare -- keep this formula in sync with it
// (Go's golden test pins that side).
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

// Maps the backend Complexity() enum (internal/pwanalysis) to the app's
// character-class notation (same tokens as the Policies page) so the chart axis
// reads "a–z A–Z 0–9 !@#" instead of "mixedalphaspecialnum".
const COMPLEXITY_LABELS: Record<string, string> = {
  loweralpha: "a–z",
  upperalpha: "A–Z",
  numeric: "0–9",
  special: "!@#",
  loweralphanum: "a–z 0–9",
  upperalphanum: "A–Z 0–9",
  mixedalpha: "a–z A–Z",
  loweralphaspecial: "a–z !@#",
  upperalphaspecial: "A–Z !@#",
  specialnum: "0–9 !@#",
  mixedalphanum: "a–z A–Z 0–9",
  loweralphaspecialnum: "a–z 0–9 !@#",
  mixedalphaspecial: "a–z A–Z !@#",
  upperalphaspecialnum: "A–Z 0–9 !@#",
  mixedalphaspecialnum: "a–z A–Z 0–9 !@#",
  none: "(none)",
}
export function complexityLabel(key: string): string {
  return COMPLEXITY_LABELS[key] ?? key
}

// Count of cracked accounts per complexity class (desc).
export function complexityCounts(accts: Account[]): Bar[] {
  const m: Record<string, number> = {}
  for (const a of accts) if (a.cracked && a.complexity) m[a.complexity] = (m[a.complexity] || 0) + 1
  return Object.entries(m)
    .map(([name, value]) => ({ name: complexityLabel(name), value }))
    .sort((a, b) => b.value - a.value)
}

// Controlled objects buckets (all accounts with enrichment data).
export function controlledObjectsBuckets(accts: Account[]): Bar[] {
  const labels = ["0", "1–10", "11–50", "51–100", "101–500", "500+"]
  const c = [0, 0, 0, 0, 0, 0]
  for (const a of accts) {
    const n = a.controlled_object_count
    if (n <= 0) c[0]++
    else if (n <= 10) c[1]++
    else if (n <= 50) c[2]++
    else if (n <= 100) c[3]++
    else if (n <= 500) c[4]++
    else c[5]++
  }
  return labels.map((name, i) => ({ name, value: c[i] })).filter((b) => b.value > 0)
}

// Password age buckets (accounts with pwd_last_set > 0, in days since last set).
export function passwordAgeBuckets(accts: Account[]): Bar[] {
  const now = Date.now() / 1000
  const labels = ["< 30d", "30–90d", "90–180d", "180–365d", "1–2y", "2y+"]
  const c = [0, 0, 0, 0, 0, 0]
  for (const a of accts) {
    if (!a.pwd_last_set || a.pwd_last_set <= 0) continue
    const days = (now - a.pwd_last_set) / 86400
    if (days < 30) c[0]++
    else if (days < 90) c[1]++
    else if (days < 180) c[2]++
    else if (days < 365) c[3]++
    else if (days < 730) c[4]++
    else c[5]++
  }
  return labels.map((name, i) => ({ name, value: c[i] })).filter((b) => b.value > 0)
}

// Accounts with "never expires" flag set (from BloodHound enrichment).
export function neverExpiresCount(accts: Account[]): number {
  return accts.filter((a) => a.pwd_never_expires === true).length
}

// Accounts escalated by shared-DA lateral movement detection.
export function escalatedBySharedDA(accts: Account[]): Account[] {
  return accts.filter((a) => a.escalated_by_shared_da).sort((a, b) => b.risk_score - a.risk_score)
}

// Top N accounts by controlled object count (the privilege hotspots).
export function topControlled(accts: Account[], n: number): Account[] {
  return accts
    .filter((a) => a.controlled_object_count > 0)
    .sort((a, b) => b.controlled_object_count - a.controlled_object_count)
    .slice(0, n)
}

// Similarity distribution among cracked accounts (buckets by similarity score).
export function similarityBuckets(accts: Account[]): Bar[] {
  const labels = ["< 0.5", "0.5–0.7", "0.7–0.8", "0.8–0.9", "0.9+"]
  const c = [0, 0, 0, 0, 0]
  for (const a of accts) {
    const s = a.similarity_score ?? 0
    if (s <= 0) continue // not computed or no similarity
    if (s < 0.5) c[0]++
    else if (s < 0.7) c[1]++
    else if (s < 0.8) c[2]++
    else if (s < 0.9) c[3]++
    else c[4]++
  }
  return labels.map((name, i) => ({ name, value: c[i] })).filter((b) => b.value > 0)
}

export interface AxisFactor { name: string; value: number; color: string }
export interface TierFactorBars {
  tier: string
  color: string
  exposure: AxisFactor[]
  impact: AxisFactor[]
  impactKnown: boolean // false when no account in this tier is enriched (impact greyed)
}

// Coalesce a possibly-absent (omitempty) breakdown key to 0. Missing = 0, never "unknown".
const bdv = (a: Account, k: keyof NonNullable<Account["score_breakdown"]>): number => {
  const v = a.score_breakdown?.[k]
  return typeof v === "number" ? v : 0
}

const EXP_FACTORS: [string, keyof NonNullable<Account["score_breakdown"]>, string][] = [
  ["Weakness", "weakness_score", "#fbbf24"],
  ["HIBP floor", "hibp_floor", "#fb7185"],
  ["Cracked floor", "cracked_floor", "#f472b6"],
  ["Reuse", "reuse_bump", "#a78bfa"],
  ["Roastable", "roastable_bump", "#38bdf8"],
  ["Age", "age_penalty", "#2dd4bf"],
]
const IMP_FACTORS: [string, keyof NonNullable<Account["score_breakdown"]>, string][] = [
  ["Privilege", "privilege_sub_score", "#22d3ee"],
  ["DA path", "da_component", "#fb7185"],
  ["Domain", "domain_modifier", "#a3e635"],
]

// axisFactorBars: per-tier averaged breakdown SUB-SCORES (already in score-points,
// commensurable within an axis). Replaces the misleading rescaled radar (v1 read
// structural zeros). The Impact group is greyed when no account in the tier was
// BloodHound-enriched (impactKnown=false), since Impact is genuinely Unknown there.
export function axisFactorBars(accts: Account[]): TierFactorBars[] {
  const tiers: [string, string][] = [
    ["Critical", "#fb7185"],
    ["High", "#fbbf24"],
    ["Medium", "#a3e635"],
    ["Low", "#22d3ee"],
  ]
  const out: TierFactorBars[] = []
  for (const [tier, color] of tiers) {
    const group = accts.filter((a) => a.risk_level === tier && a.score_breakdown)
    if (group.length === 0) continue
    // Use the shared predicate (impact_known AND impact_score !== null) so this
    // surface can't drift from the matrix/table; a malformed known-but-null payload
    // is correctly treated as not-enriched rather than averaged in as a zero.
    const enriched = group.filter((a) => impactIsKnown(a))
    const avg = (rows: Account[], k: keyof NonNullable<Account["score_breakdown"]>) =>
      rows.length ? Math.round((rows.reduce((s, a) => s + bdv(a, k), 0) / rows.length) * 100) / 100 : 0
    out.push({
      tier,
      color,
      exposure: EXP_FACTORS.map(([name, k, c]) => ({ name, value: avg(group, k), color: c })),
      impact: IMP_FACTORS.map(([name, k, c]) => ({ name, value: avg(enriched, k), color: c })),
      impactKnown: enriched.length > 0,
    })
  }
  return out
}

// passwordAgeScatter: pwd_last_set (days ago) vs risk score scatter data.
export function passwordAgeScatter(accts: Account[]): Series[] {
  const now = Date.now() / 1000
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
        .filter((a) => a.risk_level === name && a.pwd_last_set && a.pwd_last_set > 0)
        .map((a) => ({ x: Math.floor((now - a.pwd_last_set!) / 86400), y: a.risk_score })),
    }))
    .filter((s) => s.points.length > 0)
}

// expirationSplit: pie data for password expiration status.
export function expirationSplit(accts: Account[]): Slice[] {
  let expires = 0, neverExpires = 0, unknown = 0
  for (const a of accts) {
    if (a.pwd_never_expires === true) neverExpires++
    else if (a.pwd_never_expires === false) expires++
    else unknown++
  }
  return [
    { name: "Expires", value: expires, color: "#34d399" },
    { name: "Never expires", value: neverExpires, color: "#fb7185" },
    { name: "Unknown", value: unknown, color: "#475569" },
  ].filter((s) => s.value > 0)
}

// topRiskiest: top N accounts by risk_score across all domains.
export function topRiskiest(accts: Account[], n: number): Account[] {
  return [...accts].sort((a, b) => b.risk_score - a.risk_score).slice(0, n)
}

// --- Network graph data ---

export interface GraphNode { id: string; label: string; size: number; color: string }
export interface GraphEdge { source: string; target: string; weight: number; label?: string }

// crossDomainReuseGraph: domains as nodes, edges between domains that GENUINELY share a
// credential (co-occur in a Report reuse group). Mirrors exposure.ts:crossDomainBridges --
// no fabricated links. accts is used only for node sizing/color.
export function crossDomainReuseGraph(report: Report | null, accts: Account[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  if (!report) return { nodes: [], edges: [] }
  const domainMap = new Map<string, { total: number; critical: number }>()
  for (const a of accts) {
    const d = domainMap.get(a.domain) ?? { total: 0, critical: 0 }
    d.total++
    if (a.risk_level === "Critical") d.critical++
    domainMap.set(a.domain, d)
  }
  const pairWeight = new Map<string, number>()
  const connected = new Set<string>()
  for (const g of [...report.cracked_reuse, ...report.uncracked_reuse]) {
    const doms = [...new Set(g.members.map((m) => m.domain))].sort()
    if (doms.length < 2) continue
    for (let i = 0; i < doms.length; i++) {
      for (let j = i + 1; j < doms.length; j++) {
        const key = `${doms[i]}|${doms[j]}`
        pairWeight.set(key, (pairWeight.get(key) ?? 0) + g.size)
        connected.add(doms[i])
        connected.add(doms[j])
      }
    }
  }
  if (pairWeight.size === 0) return { nodes: [], edges: [] }
  const nodes: GraphNode[] = [...connected].map((d) => {
    const s = domainMap.get(d) ?? { total: 0, critical: 0 }
    const color = s.critical > 20 ? "#fb7185" : s.critical > 5 ? "#fbbf24" : "#22d3ee"
    return { id: d, label: d, size: 12 + Math.sqrt(s.total) * 2, color }
  })
  const edges: GraphEdge[] = [...pairWeight].map(([key, w]) => {
    const [source, target] = key.split("|")
    return { source, target, weight: Math.max(1, Math.ceil(w / 10)), label: `${w} shared` }
  })
  return { nodes, edges }
}

// similarityNetwork: builds a cluster of passwords that are similar to each other.
// Uses the similarity_score field — accounts with sim > 0.7 are linked.
// Returns nodes = accounts (labeled by username), edges = similarity links.
export function similarityNetwork(accts: Account[], maxNodes: number = 60): { nodes: GraphNode[]; edges: GraphEdge[] } {
  // Only cracked accounts with similarity data
  const candidates = accts.filter((a) => a.cracked && (a.similarity_score ?? 0) >= 0.7)
  if (candidates.length < 2) return { nodes: [], edges: [] }

  // Take the top N by similarity score to keep the graph readable
  const sorted = [...candidates].sort((a, b) => (b.similarity_score ?? 0) - (a.similarity_score ?? 0)).slice(0, maxNodes)

  const nodes: GraphNode[] = sorted.map((a) => ({
    id: `${a.domain}/${a.username}`,
    label: a.username,
    size: 10 + (a.similarity_score ?? 0) * 12,
    color: a.risk_level === "Critical" ? "#fb7185" : a.risk_level === "High" ? "#fbbf24" : a.risk_level === "Medium" ? "#a3e635" : "#22d3ee",
  }))

  // Real edges from server-computed similar peers (same-domain). Only link peers
  // that are themselves nodes; dedup undirected pairs.
  const nodeIds = new Set(nodes.map((n) => n.id))
  const edges: GraphEdge[] = []
  const seen = new Set<string>()
  for (const a of sorted) {
    const srcId = `${a.domain}/${a.username}`
    for (const p of a.similar_peers ?? []) {
      const dstId = `${p.domain}/${p.username}`
      if (!nodeIds.has(dstId) || dstId === srcId) continue
      const key = srcId < dstId ? `${srcId}|${dstId}` : `${dstId}|${srcId}`
      if (seen.has(key)) continue
      seen.add(key)
      edges.push({
        source: srcId,
        target: dstId,
        weight: Math.max(1, Math.round(p.score * 3)),
        label: `${Math.round(p.score * 100)}%`,
      })
    }
  }
  return { nodes, edges }
}

// kpiCounts returns the four primary Overview KPIs from the authoritative Summary counts
// (matching the report/export), falling back to client-derived counts only while Summary is
// still loading (null). Kills the client-predicate-vs-Go-counter drift.
export function kpiCounts(
  summary: Summary | null,
  accounts: Account[],
): { total: number; cracked: number; breached: number; da: number } {
  return {
    total: summary?.total_accounts ?? accounts.length,
    cracked: summary?.cracked ?? accounts.filter((a) => a.cracked).length,
    breached: summary?.hibp_breached ?? accounts.filter((a) => a.hibp_breached).length,
    da: summary?.da_pathways ?? accounts.filter((a) => hasDA(a.da_domains)).length,
  }
}
