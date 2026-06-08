import { createContext, useContext, useEffect, useState, type ReactNode } from "react"
import { api, ApiError, type Account } from "./api"
import { useAudits } from "./auditsData"

interface AccountsState {
  accounts: Account[] | null
  error: string
}

const Ctx = createContext<AccountsState | null>(null)

// AccountsProvider fetches the (redacted) account set for the active audit and
// shares it across the Accounts / Actionable / Domains views. It re-fetches when
// the active audit changes.
export function AccountsProvider({ children }: { children: ReactNode }) {
  const { activeId } = useAudits()
  const [accounts, setAccounts] = useState<Account[] | null>(null)
  const [error, setError] = useState("")

  useEffect(() => {
    if (!activeId) {
      setAccounts(null)
      return
    }
    let active = true
    setAccounts(null) // show loading while the new audit's data arrives
    setError("")
    api
      .accounts()
      .then((a) => {
        if (active) setAccounts(a)
      })
      .catch((e) => {
        if (active) setError(e instanceof ApiError ? e.message : "failed to load accounts")
      })
    return () => {
      active = false
    }
  }, [activeId])

  return <Ctx.Provider value={{ accounts, error }}>{children}</Ctx.Provider>
}

export function useAccountsData(): AccountsState {
  const c = useContext(Ctx)
  if (!c) throw new Error("useAccountsData must be used within AccountsProvider")
  return c
}
