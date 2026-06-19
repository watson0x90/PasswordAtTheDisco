import type { Account } from "../api"
import { useAccountsData } from "../accountsData"
import { useAccountDrawer } from "../accountDrawer"

// AccountLink renders a username as a button that opens the shared account drawer.
// Resolves the full Account from `accounts` (when provided, e.g. Compare's combined
// two-audit list) or the active-audit list. Falls back to plain text when not found.
export function AccountLink({ username, domain, accounts }: { username: string; domain: string; accounts?: Account[] }) {
  const { accounts: active } = useAccountsData()
  const { openAccount } = useAccountDrawer()
  const list = accounts ?? active ?? []
  const full = list.find((a) => a.username === username && a.domain === domain)
  if (!full) return <span>{username}</span>
  return (
    <button className="link-btn" onClick={() => openAccount(full)}>
      {username}
    </button>
  )
}
