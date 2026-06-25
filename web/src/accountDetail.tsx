import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react"
import type { Account } from "./api"
import { AccountDetail } from "./components/AccountDetail"
import { type Crumb, pushCrumb, popCrumb, jumpCrumb } from "./trail"

interface DetailState {
  open: (a: Account) => void
  pushPeer: (c: Crumb) => void
  back: () => void
  jump: (index: number) => void
  close: () => void
}
const Ctx = createContext<DetailState | null>(null)

// AccountDetailProvider owns the pivot trail and renders the full-screen detail overlay
// when the trail is non-empty. Mounts inside AccountsProvider (reads accounts) and wraps
// AccountDrawerProvider (so the drawer's "Expand details" button can call open()).
export function AccountDetailProvider({ children }: { children: ReactNode }) {
  const [trail, setTrail] = useState<Crumb[]>([])
  const open = useCallback((a: Account) => setTrail([{ username: a.username, domain: a.domain }]), [])
  const pushPeer = useCallback((c: Crumb) => setTrail((t) => pushCrumb(t, c)), [])
  const back = useCallback(() => setTrail((t) => popCrumb(t)), [])
  const jump = useCallback((i: number) => setTrail((t) => jumpCrumb(t, i)), [])
  const close = useCallback(() => setTrail([]), [])
  const value = useMemo(() => ({ open, pushPeer, back, jump, close }), [open, pushPeer, back, jump, close])
  return (
    <Ctx.Provider value={value}>
      {children}
      {trail.length > 0 && (
        <AccountDetail trail={trail} onBack={back} onJump={jump} onPivot={pushPeer} onClose={close} />
      )}
    </Ctx.Provider>
  )
}

export function useAccountDetail(): DetailState {
  const c = useContext(Ctx)
  if (!c) throw new Error("useAccountDetail must be used within AccountDetailProvider")
  return c
}
