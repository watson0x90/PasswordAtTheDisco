import type { Account, IngestEvent } from "./api"

export interface DomainRow {
  domain: string
  accounts: number
  cracked: number
  enriched: "fresh" | "stale" | "none"
  loadedAt?: string
}

// perDomainStatus derives the Audit Data table rows from the live accounts list
// + the ingest history. Enrichment freshness compares each domain's latest dump
// load time against the audit's latest enrichment time.
export function perDomainStatus(accounts: Account[], ingests: IngestEvent[]): DomainRow[] {
  const lastEnrich = ingests
    .filter((e) => e.kind === "enrich")
    .map((e) => e.at)
    .sort()
    .pop()
  const loadedAt = new Map<string, string>()
  for (const e of ingests) {
    if (e.kind === "dump" && e.domain) {
      const prev = loadedAt.get(e.domain)
      if (!prev || e.at > prev) loadedAt.set(e.domain, e.at)
    }
  }
  const byDomain = new Map<string, DomainRow>()
  for (const a of accounts) {
    let row = byDomain.get(a.domain)
    if (!row) {
      row = { domain: a.domain, accounts: 0, cracked: 0, enriched: "none", loadedAt: loadedAt.get(a.domain) }
      byDomain.set(a.domain, row)
    }
    row.accounts++
    if (a.cracked) row.cracked++
  }
  for (const row of byDomain.values()) {
    if (!lastEnrich) row.enriched = "none"
    else if (row.loadedAt && row.loadedAt > lastEnrich) row.enriched = "stale"
    else row.enriched = "fresh"
  }
  return [...byDomain.values()].sort((a, b) => b.accounts - a.accounts)
}
