import { createContext, useContext, useEffect, useState, type ReactNode } from "react"
import { api, ApiError, type Account } from "./api"

interface AccountsState {
  accounts: Account[] | null
  error: string
}

const Ctx = createContext<AccountsState | null>(null)

// AccountsProvider fetches the (redacted) account set once and shares it across
// the Accounts / Actionable / Domains views so switching tabs doesn't refetch.
export function AccountsProvider({ children }: { children: ReactNode }) {
  const [accounts, setAccounts] = useState<Account[] | null>(null)
  const [error, setError] = useState("")

  useEffect(() => {
    let active = true
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
  }, [])

  return <Ctx.Provider value={{ accounts, error }}>{children}</Ctx.Provider>
}

export function useAccountsData(): AccountsState {
  const c = useContext(Ctx)
  if (!c) throw new Error("useAccountsData must be used within AccountsProvider")
  return c
}
