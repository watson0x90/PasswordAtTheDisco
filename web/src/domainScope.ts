import type { Account, Report, ReportAccount, ReuseGroup, Summary } from "./api"
import { neverExpiresCount, posture } from "./insights"
import { hasDA } from "./util"

// credentialObtainable mirrors Go model.CredentialObtainable (NO enabled gate — the
// caller checks !enabled separately). insights.isReachable is the same condition but
// additionally requires enabled, so it can't be reused for the dormant (disabled) case.
const credentialObtainable = (a: Account): boolean =>
  !!a.cracked || !!a.hibp_breached || !!a.escalated_by_shared_da || !!a.escalated_by_mass_reuse

// dormant_privileged mirrors Go store.go DormantPrivileged exactly: disabled, privileged
// (controls Tier-0 or has a DA pathway), AND credential-obtainable.
function isDormantPrivileged(a: Account): boolean {
  return !a.enabled && (!!a.controls_tier0 || hasDA(a.da_domains)) && credentialObtainable(a)
}

// domainSummary builds a Summary for an already-domain-filtered account set so the
// per-domain page can render the same Overview as the org view. Counts mirror the
// Go model.Summary semantics surfaced in the Dashboard KPIs; posture reuses the
// client posture() builder (kept in sync with the Go authoritative posture). It is
// intentionally NOT the server summary — breach_impact is omitted (no client
// estimator) and generated_at is copied from the org summary (same scoring run).
export function domainSummary(domainAccounts: Account[], orgSummary: Summary): Summary {
  const riskCounts: Record<string, number> = {}
  for (const a of domainAccounts) {
    riskCounts[a.risk_level] = (riskCounts[a.risk_level] ?? 0) + 1
  }
  return {
    total_accounts: domainAccounts.length,
    cracked: domainAccounts.filter((a) => a.cracked).length,
    hibp_breached: domainAccounts.filter((a) => a.hibp_breached).length,
    da_pathways: domainAccounts.filter((a) => hasDA(a.da_domains)).length,
    risk_counts: riskCounts,
    posture: posture(domainAccounts),
    generated_at: orgSummary.generated_at,
    disabled_accounts: domainAccounts.filter((a) => !a.enabled).length,
    never_expires: neverExpiresCount(domainAccounts),
    stale_passwords: domainAccounts.filter((a) => (a.days_out_of_compliance ?? 0) > 0).length,
    escalated_by_shared_da: domainAccounts.filter((a) => a.escalated_by_shared_da).length,
    escalated_by_mass_reuse: domainAccounts.filter((a) => a.escalated_by_mass_reuse).length,
    policy_violations: domainAccounts.filter((a) => a.cracked && !a.meets_policy).length,
    high_controlled: domainAccounts.filter((a) => (a.controlled_object_count ?? 0) > 100).length,
    dormant_privileged: domainAccounts.filter(isDormantPrivileged).length,
    // breach_impact intentionally omitted — see header comment.
  }
}

const inDomain = (domain: string) => (x: ReportAccount) => x.domain === domain
const groupTouchesDomain = (domain: string) => (g: ReuseGroup) =>
  g.members.some((m) => m.domain === domain)

// domainReport scopes an org Report to a single domain for the per-domain Overview's
// report-driven panels (the cross-domain reuse graph + Insights). Per-account lists
// are filtered to the domain; reuse groups are kept when ANY member is in the domain
// (so cross-domain clusters the domain participates in remain visible). violation_counts
// is passed through (labels only — low-stakes). total/cracked/uncracked come from the
// filtered domain accounts when provided, else fall back to the org report's totals.
export function domainReport(
  orgReport: Report | null,
  domain: string,
  domainAccounts?: Account[],
): Report | null {
  if (!orgReport) return null
  const keep = inDomain(domain)
  const keepGroup = groupTouchesDomain(domain)
  const crackedCount = domainAccounts?.filter((a) => a.cracked).length
  return {
    total_accounts: domainAccounts ? domainAccounts.length : orgReport.total_accounts,
    cracked_count: crackedCount ?? orgReport.cracked_count,
    uncracked_count: domainAccounts ? domainAccounts.length - (crackedCount ?? 0) : orgReport.uncracked_count,
    da_pathways: orgReport.da_pathways.filter(keep),
    cracked: orgReport.cracked.filter(keep),
    cracked_reuse: orgReport.cracked_reuse.filter(keepGroup),
    uncracked_reuse: orgReport.uncracked_reuse.filter(keepGroup),
    hibp_exposed: orgReport.hibp_exposed.filter(keep),
    weak_passwords: orgReport.weak_passwords.filter(keep),
    violation_counts: orgReport.violation_counts,
    escalated_by_shared_da: orgReport.escalated_by_shared_da.filter(keep),
    high_controlled: orgReport.high_controlled.filter(keep),
    never_expires: orgReport.never_expires.filter(keep),
    stale_passwords: orgReport.stale_passwords.filter(keep),
    kerberoastable: orgReport.kerberoastable.filter(keep),
    asrep_roastable: orgReport.asrep_roastable.filter(keep),
  }
}
