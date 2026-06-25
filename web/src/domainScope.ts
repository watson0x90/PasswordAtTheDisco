import type { Account, Summary } from "./api"
import { escalatedBySharedDA, neverExpiresCount, posture } from "./insights"
import { hasDA } from "./util"

// A domain-scoped account is "privileged" if it controls Tier-0, has a DA pathway,
// or is a high-privilege controller (>100 controlled objects). Used for the
// dormant-privileged (disabled + privileged) count surfaced in the posture card.
function isPrivileged(a: Account): boolean {
  return !!a.controls_tier0 || hasDA(a.da_domains) || (a.controlled_object_count ?? 0) > 100
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
    escalated_by_shared_da: escalatedBySharedDA(domainAccounts).length,
    escalated_by_mass_reuse: domainAccounts.filter((a) => a.escalated_by_mass_reuse).length,
    policy_violations: domainAccounts.filter((a) => a.cracked && !a.meets_policy).length,
    high_controlled: domainAccounts.filter((a) => (a.controlled_object_count ?? 0) > 100).length,
    dormant_privileged: domainAccounts.filter((a) => !a.enabled && isPrivileged(a)).length,
    // breach_impact intentionally omitted — see header comment.
  }
}
