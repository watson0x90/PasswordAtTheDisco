import type { Account, Report, ReportAccount } from "./api"
import { hasDA } from "./util"

export interface BridgeCluster {
  domains: string[]
  size: number
  cracked: boolean
  hasDA: boolean
  hibpMax: number
  members: ReportAccount[]
}
export interface CrossDomain {
  clusters: BridgeCluster[]
  domains: string[]
}
export interface WorklistRow {
  account: Account
  priority: number
  reasons: string[]
}

// exposureHeadline — the three exec "blast radius" numbers.
export function exposureHeadline(
  accounts: Account[],
  report: Report,
): { crackedDA: number; crackedHibp: number; crossDomainGroups: number; domainsSpanned: number } {
  let crackedDA = 0
  let crackedHibp = 0
  for (const a of accounts) {
    if (a.cracked && hasDA(a.da_domains)) crackedDA++
    if (a.cracked && a.hibp_breached) crackedHibp++
  }
  const spanned = new Set<string>()
  let crossDomainGroups = 0
  for (const g of [...report.cracked_reuse, ...report.uncracked_reuse]) {
    const doms = new Set(g.members.map((m) => m.domain))
    if (doms.size >= 2) {
      crossDomainGroups++
      doms.forEach((d) => spanned.add(d))
    }
  }
  return { crackedDA, crackedHibp, crossDomainGroups, domainsSpanned: spanned.size }
}

// crossDomainBridges — ranked cross-domain shared-credential clusters.
export function crossDomainBridges(report: Report): CrossDomain {
  const clusters: BridgeCluster[] = []
  const domains = new Set<string>()
  for (const g of [...report.cracked_reuse, ...report.uncracked_reuse]) {
    const doms = [...new Set(g.members.map((m) => m.domain))].sort()
    if (doms.length < 2) continue
    doms.forEach((d) => domains.add(d))
    clusters.push({
      domains: doms, size: g.size, cracked: g.cracked, hasDA: g.has_da_pathway,
      hibpMax: g.hibp_breach_count, members: g.members,
    })
  }
  // DA clusters first, then by blast radius = size × distinct-domain count.
  clusters.sort(
    (x, y) =>
      (y.hasDA ? 1 : 0) - (x.hasDA ? 1 : 0) ||
      y.size * y.domains.length - x.size * x.domains.length,
  )
  return { clusters, domains: [...domains].sort() }
}

// hibpTriage — Tier 1 (cracked+breached) vs Tier 2 (breached, not cracked).
export function hibpTriage(report: Report): { tier1: ReportAccount[]; tier2: ReportAccount[] } {
  const bySeverity = (a: ReportAccount, b: ReportAccount) =>
    b.hibp_breach_count - a.hibp_breach_count || b.risk_score - a.risk_score
  return {
    tier1: report.hibp_exposed.filter((a) => a.cracked).sort(bySeverity),
    tier2: report.hibp_exposed.filter((a) => !a.cracked).sort(bySeverity),
  }
}

// blastRadius — ranked remediation worklist with reason badges.
export function blastRadius(accounts: Account[]): WorklistRow[] {
  const rows: WorklistRow[] = []
  for (const a of accounts) {
    const reasons: string[] = []
    let priority = 0
    if (hasDA(a.da_domains)) { priority += 3; reasons.push("DA") }
    if (a.hibp_breached) { priority += 2; reasons.push(`HIBP ${a.hibp_breach_count.toLocaleString()}`) }
    if (a.cracked) { priority += 1; reasons.push("Cracked") }
    if (a.shared_with > 0) { priority += 1; reasons.push(`Shared ${a.shared_with}`) }
    if (!a.enabled) reasons.push("disabled")
    if (priority > 0) rows.push({ account: a, priority, reasons })
  }
  rows.sort((x, y) => y.priority - x.priority || y.account.risk_score - x.account.risk_score)
  return rows
}
