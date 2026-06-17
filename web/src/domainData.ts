import type { Account, Report, ReuseGroup, ReportAccount } from "./api"

// Reuse clusters that include at least one account in `domain` (a cluster may
// span domains; it's listed under each domain it touches). Sorted by size desc.
export function domainReuseClusters(report: Report, domain: string): { cracked: ReuseGroup[]; uncracked: ReuseGroup[] } {
  const touches = (g: ReuseGroup) => g.members.some((m) => m.domain === domain)
  const bySize = (a: ReuseGroup, b: ReuseGroup) => b.size - a.size
  return {
    cracked: report.cracked_reuse.filter(touches).sort(bySize),
    uncracked: report.uncracked_reuse.filter(touches).sort(bySize),
  }
}

// DA-pathway accounts in this domain, highest risk first.
export function domainDAPaths(report: Report, domain: string): ReportAccount[] {
  return report.da_pathways.filter((a) => a.domain === domain).sort((a, b) => b.risk_score - a.risk_score)
}

// Top-N cracked accounts by risk score (the remediation shortlist).
export function domainQuickWins(domainAccts: Account[], n: number): Account[] {
  return domainAccts.filter((a) => a.cracked).sort((a, b) => b.risk_score - a.risk_score).slice(0, n)
}

// Policy compliance over the domain's accounts.
export function domainPolicy(domainAccts: Account[]): { meets: number; fails: number; disabled: number } {
  let meets = 0, fails = 0, disabled = 0
  for (const a of domainAccts) {
    if (!a.enabled) { disabled++; continue }
    if (a.cracked) { if (a.meets_policy) meets++; else fails++ }
  }
  return { meets, fails, disabled }
}

// Wordlist-weakness counts over the domain's cracked accounts.
export function domainWordlist(domainAccts: Account[]): { common: number; dictionary: number; banned: number; keyboard: number } {
  let common = 0, dictionary = 0, banned = 0, keyboard = 0
  for (const a of domainAccts) {
    if (!a.cracked) { continue }
    if (a.is_common) { common++ }
    if (a.is_dictionary_word) { dictionary++ }
    if ((a.banned_word_count ?? 0) > 0) { banned++ }
    if ((a.keyboard_pattern_count ?? 0) > 0) { keyboard++ }
  }
  return { common, dictionary, banned, keyboard }
}
