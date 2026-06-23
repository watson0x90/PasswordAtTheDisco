import type { Account } from "./api"

export interface AccountKey {
  username: string
  domain: string
}

// selectedAccount resolves the LIVE account for an open drawer.
//
// The drawer is opened with a captured Account object (e.g. a row from a table).
// After a rescore the shared accounts list refetches with fresh risk_vector /
// scores, but the captured object is stale. To keep an open drawer in sync we
// re-derive from the live list by (username, domain) key each render.
//
// Fallback: if the keyed account is not present in `accounts` (e.g. a Compare
// drawer opened for an account that belongs to a non-active audit, or the active
// list is still loading), return the captured object so the drawer keeps showing
// the data it was opened with instead of vanishing.
export function selectedAccount(
  accounts: Account[] | null,
  captured: Account | null,
): Account | null {
  if (!captured) return null
  const live = (accounts ?? []).find(
    (a) => a.username === captured.username && a.domain === captured.domain,
  )
  return live ?? captured
}
