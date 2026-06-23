import type { Account } from "./api"
import { isProvisional } from "./matrix"

// unenrichedAccounts: the accounts with Unknown Impact (no BloodHound coverage), using
// the SAME predicate as the Overview "Impact Unknown" KPI so counts can't drift.
export function unenrichedAccounts(accounts: Account[]): Account[] {
  return accounts.filter(isProvisional)
}

export type CoverageWhy =
  | { kind: "all-covered"; total: number }
  | { kind: "never-run"; count: number }
  | { kind: "ran-unmatched"; count: number }

// coverageWhy diagnoses the audit-level reason from the un-enriched count + whether a
// BloodHound enrichment has ever run on this audit (an "enrich" ingest event exists).
export function coverageWhy(o: { unenrichedCount: number; totalCount: number; enrichRan: boolean }): CoverageWhy {
  if (o.unenrichedCount === 0) return { kind: "all-covered", total: o.totalCount }
  if (!o.enrichRan) return { kind: "never-run", count: o.unenrichedCount }
  return { kind: "ran-unmatched", count: o.unenrichedCount }
}

function csvField(s: string): string {
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

// coverageCsv builds a CSV of the un-enriched accounts. NON-SECRET columns only --
// never password or NT hash (they aren't even on the redacted Account).
export function coverageCsv(accounts: Account[]): string {
  const header = "Username,Domain,Cracked,Exposure level"
  const rows = accounts.map((a) =>
    [csvField(a.username), csvField(a.domain), a.cracked ? "yes" : "no", csvField(a.risk_level)].join(","),
  )
  return [header, ...rows].join("\n") + "\n"
}
