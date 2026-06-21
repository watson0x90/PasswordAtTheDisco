import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react"
import { api, type Me } from "./api"

type Status = "loading" | "authenticated" | "anonymous"

interface AuthState {
  status: Status
  me: Me | null
  autoLocked: boolean // store auto-locked for inactivity (drives the unlock banner)
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  refresh: () => Promise<void>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>("loading")
  const [me, setMe] = useState<Me | null>(null)
  const [autoLocked, setAutoLocked] = useState(false)

  // Track the latest status for event handlers (registered once) without re-binding.
  const statusRef = useRef(status)
  statusRef.current = status

  // The API layer broadcasts patd:locked on any 423 (idle auto-lock). Reflect it
  // so the app returns to the unlock screen instead of stranding a raw error.
  useEffect(() => {
    const onLocked = () => {
      setMe((prev) => (prev ? { ...prev, store_unlocked: false } : prev))
      setAutoLocked(true)
    }
    window.addEventListener("patd:locked", onLocked)
    return () => window.removeEventListener("patd:locked", onLocked)
  }, [])

  // The API layer broadcasts patd:unauthorized on any 401 (the session is gone:
  // server restart wiped the in-memory session store, or it hit idle/absolute
  // expiry). Return to the login screen so the SPA doesn't sit in a stale
  // "authenticated" state where mounted pollers keep 401-ing. Guarded to only act
  // when we currently think we're authenticated, so a failed-login 401 (already
  // anonymous) doesn't interfere with the login form's own error handling.
  useEffect(() => {
    const onUnauthorized = () => {
      if (statusRef.current !== "authenticated") return
      setMe(null)
      setStatus("anonymous")
      setAutoLocked(false)
    }
    window.addEventListener("patd:unauthorized", onUnauthorized)
    return () => window.removeEventListener("patd:unauthorized", onUnauthorized)
  }, [])

  // Bootstrap: ask the server who we are (valid session cookie?).
  useEffect(() => {
    let active = true
    api
      .me()
      .then((m) => {
        if (!active) return
        if (m.authenticated === false) {
          setStatus("anonymous")
          return
        }
        setMe(m)
        setStatus("authenticated")
      })
      .catch(() => {
        // network/other: treat as anonymous so the login screen shows.
        if (active) setStatus("anonymous")
      })
    return () => {
      active = false
    }
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const m = await api.login(username, password)
    setMe(m)
    setStatus("authenticated")
    setAutoLocked(false)
  }, [])

  const logout = useCallback(async () => {
    try {
      if (me) await api.logout(me.csrf_token)
    } finally {
      setMe(null)
      setStatus("anonymous")
    }
  }, [me])

  // refresh re-reads /me (e.g. after unlocking the store, to pick up the new state).
  // Guard on the authenticated flag like the bootstrap effect: if the session
  // lapsed between actions, /me now returns 200 {authenticated:false} (not a 401),
  // so fall back to anonymous rather than storing a payload-less Me.
  const refresh = useCallback(async () => {
    const m = await api.me()
    if (m.authenticated === false) {
      setMe(null)
      setStatus("anonymous")
      return
    }
    setMe(m)
    setAutoLocked(false)
  }, [])

  return (
    <AuthContext.Provider value={{ status, me, autoLocked, login, logout, refresh }}>{children}</AuthContext.Provider>
  )
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error("useAuth must be used within AuthProvider")
  return ctx
}
