import type { Account } from "./api"
import { hasDA, RISK_RANK } from "./util"
import { isProvisional } from "./matrix"
export interface WorklistItem { account: Account; priority: number; reasons: string[]; action: string }
// Ranked remediation worklist: a composite priority (so ties break), human reasons,
// and a recommended action. Derived from the redacted account fields.
export function priorityWorklist(accounts: Account[]): WorklistItem[] {
  const items: WorklistItem[] = []
  for (const a of accounts) {
    const reasons: string[] = []
    let p = 0
    const da = hasDA(a.da_domains)
    if (da) { p += 100; reasons.push("DA path") }
    if (a.escalated_by_shared_da) { p += 50; reasons.push("Shares DA hash") }
    if (a.cracked && a.hibp_breached) { p += 40; reasons.push(`HIBP ${a.hibp_breach_count.toLocaleString()}`) }
    else if (a.cracked) { p += 25; reasons.push("Cracked") }
    if (a.shared_with > 0) { p += Math.min(20, a.shared_with); reasons.push(`Shared ${a.shared_with}`) }
    if (a.pwd_never_expires) { p += 5; reasons.push("Never expires") } // small bump: surfaces but ranks below cracked/DA/HIBP
    if (p === 0) continue
    // tie-break: raw risk (0-10) + a fraction of shared_with
    p += a.risk_score + Math.min(a.shared_with, 5) / 10
    // recommended action — most severe wins; shared/reuse outranks never-expires
    let action = "Review"
    if (da || a.escalated_by_shared_da) action = "Rotate now + review DA path"
    else if (a.cracked && a.hibp_breached) action = "Rotate now — password is public"
    else if (a.cracked) action = "Rotate password"
    else if (a.shared_with > 0) action = "Rotate (shared password)"
    else if (a.pwd_never_expires) action = "Enforce expiry"
    items.push({ account: a, priority: p, reasons, action })
  }
  return items.sort((x, y) => y.priority - x.priority)
}

export interface SegmentedWorklist {
  ranked: Account[]
  needsEnrichment: Account[]
}

// segmentWorklist splits accounts into a needs-enrichment list (Impact Unknown —
// no BloodHound coverage; segregated via matrix.ts isProvisional so it can't drift
// from the badge/matrix-Unknown surfaces, and never ordered as if low-impact) and a
// ranked list ordered Level desc, then Impact desc, then Exposure desc, then the
// engine-computed within-audit percentile desc (the final tie-break that defeats
// tier collapse). Ties with all keys equal preserve input order (stable sort).
export function segmentWorklist(accounts: Account[]): SegmentedWorklist {
  const needsEnrichment = accounts.filter((a) => isProvisional(a))
  const ranked = accounts
    .filter((a) => !isProvisional(a))
    .slice()
    .sort(
      (x, y) =>
        (RISK_RANK[y.risk_level] ?? 0) - (RISK_RANK[x.risk_level] ?? 0) ||
        (y.impact_score ?? 0) - (x.impact_score ?? 0) ||
        y.exposure_score - x.exposure_score ||
        (y.percentile ?? 0) - (x.percentile ?? 0),
    )
  return { ranked, needsEnrichment }
}
