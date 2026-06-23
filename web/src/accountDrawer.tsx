import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react"
import type { Account } from "./api"
import { AccountDrawer } from "./components/AccountDrawer"
import { useAccountsData } from "./accountsData"
import { selectedAccount } from "./selectedAccount"

interface DrawerState { openAccount: (a: Account) => void }
const Ctx = createContext<DrawerState | null>(null)

export function AccountDrawerProvider({ children }: { children: ReactNode }) {
  // `captured` is the Account object the drawer was opened with. The active
  // accounts list refetches after a rescore, so we re-derive the LIVE row by
  // (username, domain) each render — an open drawer then reflects a completed
  // rescore without a page reload. Falls back to the captured object when the
  // account isn't in the active list (e.g. a Compare cross-audit row).
  const [captured, setCaptured] = useState<Account | null>(null)
  const { accounts } = useAccountsData()
  const selected = selectedAccount(accounts, captured)
  // Stable identities: the provider now re-renders on every accounts refetch, so
  // memoize the context value + close handler to avoid churning consumers and the
  // drawer's keydown-listener effect.
  const handleClose = useCallback(() => setCaptured(null), [])
  const value = useMemo(() => ({ openAccount: setCaptured }), [])
  return (
    <Ctx.Provider value={value}>
      {children}
      {selected && <AccountDrawer account={selected} onClose={handleClose} />}
    </Ctx.Provider>
  )
}

export function useAccountDrawer(): DrawerState {
  const c = useContext(Ctx)
  if (!c) throw new Error("useAccountDrawer must be used within AccountDrawerProvider")
  return c
}
