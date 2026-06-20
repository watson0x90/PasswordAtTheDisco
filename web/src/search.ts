import type { Account } from "./api"

// filterAccounts returns accounts whose username or domain contains the query
// (case-insensitive substring), capped at `limit`. Empty query yields []. Shared
// by the command palette and the Search tab so both behave identically.
export function filterAccounts(accounts: Account[], query: string, limit = 25): Account[] {
  const q = query.trim().toLowerCase()
  if (!q) return []
  const out: Account[] = []
  for (const a of accounts) {
    if (`${a.username} ${a.domain}`.toLowerCase().includes(q)) {
      out.push(a)
      if (out.length >= limit) break
    }
  }
  return out
}
