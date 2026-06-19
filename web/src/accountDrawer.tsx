import { createContext, useContext, useState, type ReactNode } from "react"
import type { Account } from "./api"
import { AccountDrawer } from "./components/AccountDrawer"

interface DrawerState { openAccount: (a: Account) => void }
const Ctx = createContext<DrawerState | null>(null)

export function AccountDrawerProvider({ children }: { children: ReactNode }) {
  const [selected, setSelected] = useState<Account | null>(null)
  return (
    <Ctx.Provider value={{ openAccount: setSelected }}>
      {children}
      {selected && <AccountDrawer account={selected} onClose={() => setSelected(null)} />}
    </Ctx.Provider>
  )
}

export function useAccountDrawer(): DrawerState {
  const c = useContext(Ctx)
  if (!c) throw new Error("useAccountDrawer must be used within AccountDrawerProvider")
  return c
}
