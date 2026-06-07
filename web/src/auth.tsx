import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react"
import { api, ApiError, type Me } from "./api"

type Status = "loading" | "authenticated" | "anonymous"

interface AuthState {
  status: Status
  me: Me | null
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>("loading")
  const [me, setMe] = useState<Me | null>(null)

  // Bootstrap: ask the server who we are (valid session cookie?).
  useEffect(() => {
    let active = true
    api
      .me()
      .then((m) => {
        if (active) {
          setMe(m)
          setStatus("authenticated")
        }
      })
      .catch((err) => {
        if (!active) return
        if (err instanceof ApiError && err.status === 401) {
          setStatus("anonymous")
        } else {
          // network/other: treat as anonymous so the login screen shows.
          setStatus("anonymous")
        }
      })
    return () => {
      active = false
    }
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const m = await api.login(username, password)
    setMe(m)
    setStatus("authenticated")
  }, [])

  const logout = useCallback(async () => {
    try {
      if (me) await api.logout(me.csrf_token)
    } finally {
      setMe(null)
      setStatus("anonymous")
    }
  }, [me])

  return <AuthContext.Provider value={{ status, me, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error("useAuth must be used within AuthProvider")
  return ctx
}
