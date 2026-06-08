import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react"
import { api, ApiError, type AuditListItem, type AuditMeta } from "./api"
import { useAuth } from "./auth"

interface AuditsState {
  audits: AuditListItem[]
  activeId: string | null
  active: AuditListItem | null
  loading: boolean
  error: string
  refresh: () => Promise<void>
  open: (id: string) => Promise<void>
  create: (name: string, notes?: string) => Promise<AuditMeta>
  remove: (id: string) => Promise<void>
}

const Ctx = createContext<AuditsState | null>(null)

// AuditsProvider tracks the audit list and which audit this session is viewing.
// The active audit is server-side session state; the views below re-fetch when it
// changes.
export function AuditsProvider({ children }: { children: ReactNode }) {
  const { me } = useAuth()
  const csrf = me?.csrf_token ?? ""
  const [audits, setAudits] = useState<AuditListItem[]>([])
  const [activeId, setActiveId] = useState<string | null>(me?.active_audit || null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")

  const refresh = useCallback(async () => {
    try {
      setAudits(await api.listAudits())
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "failed to load audits")
    }
  }, [])

  useEffect(() => {
    refresh().finally(() => setLoading(false))
  }, [refresh])

  const open = useCallback(
    async (id: string) => {
      await api.openAudit(id, csrf)
      setActiveId(id)
    },
    [csrf],
  )

  // Auto-select an audit if the session has none (e.g. first login this session).
  useEffect(() => {
    if (!loading && !activeId && audits.length > 0) {
      open(audits[0].id).catch(() => {})
    }
  }, [loading, activeId, audits, open])

  const create = useCallback(
    async (name: string, notes = "") => {
      const meta = await api.createAudit(name, notes, csrf) // server auto-opens it
      setActiveId(meta.id)
      await refresh()
      return meta
    },
    [csrf, refresh],
  )

  const remove = useCallback(
    async (id: string) => {
      await api.deleteAudit(id, csrf)
      if (activeId === id) setActiveId(null)
      await refresh()
    },
    [csrf, activeId, refresh],
  )

  const active = audits.find((a) => a.id === activeId) ?? null

  return (
    <Ctx.Provider value={{ audits, activeId, active, loading, error, refresh, open, create, remove }}>
      {children}
    </Ctx.Provider>
  )
}

export function useAudits(): AuditsState {
  const c = useContext(Ctx)
  if (!c) throw new Error("useAudits must be used within AuditsProvider")
  return c
}
