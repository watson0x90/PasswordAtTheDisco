import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { api, type EnrichJob, type PwnedJob } from "./api"
import { useAuth } from "./auth"
import { useAudits } from "./auditsData"

interface JobsState {
  enrich: EnrichJob | null
  hibp: PwnedJob | null
  anyRunning: boolean
  refresh: () => void
}

const Ctx = createContext<JobsState | null>(null)

// hibpRunning reports whether the HIBP corpus job is mid-flight.
export const hibpRunning = (p?: string) => p === "downloading" || p === "indexing"

// computeAnyRunning is true when either background job is in progress.
export function computeAnyRunning(enrich: EnrichJob | null, hibp: PwnedJob | null): boolean {
  return enrich?.phase === "running" || hibpRunning(hibp?.phase)
}

// JobsProvider polls the two background-job endpoints (BloodHound enrichment +
// HIBP download/index) and shares their state. Both endpoints are lead-only, so
// it polls only for leads. Cadence: 5s idle, 1.5s while a job runs.
export function JobsProvider({ children }: { children: ReactNode }) {
  const { me } = useAuth()
  const { bumpData } = useAudits()
  const isLead = me?.role === "lead"
  const [enrich, setEnrich] = useState<EnrichJob | null>(null)
  const [hibp, setHibp] = useState<PwnedJob | null>(null)
  const [tick, setTick] = useState(0)
  const refresh = useCallback(() => setTick((t) => t + 1), [])

  const anyRunning = computeAnyRunning(enrich, hibp)
  const runningRef = useRef(anyRunning)
  runningRef.current = anyRunning

  const prevEnrichPhase = useRef<string | undefined>(undefined)
  useEffect(() => {
    if (prevEnrichPhase.current === "running" && enrich?.phase === "done") bumpData()
    prevEnrichPhase.current = enrich?.phase
  }, [enrich?.phase, bumpData])

  useEffect(() => {
    if (!isLead) {
      setEnrich(null)
      setHibp(null)
      return
    }
    let alive = true
    let timer: number | undefined
    const poll = async () => {
      // allSettled never rejects; a transient error on one endpoint (locked /
      // network) leaves that job's last state intact while the other still updates.
      const [e, h] = await Promise.allSettled([api.enrichJob(), api.pwnedJob()])
      if (!alive) return
      if (e.status === "fulfilled") setEnrich(e.value)
      if (h.status === "fulfilled") setHibp(h.value)
      timer = window.setTimeout(poll, runningRef.current ? 1500 : 5000)
    }
    void poll()
    return () => {
      alive = false
      if (timer) window.clearTimeout(timer)
    }
  }, [isLead, tick])

  const value = useMemo(() => ({ enrich, hibp, anyRunning, refresh }), [enrich, hibp, anyRunning, refresh])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useJobs(): JobsState {
  const c = useContext(Ctx)
  if (!c) throw new Error("useJobs must be used within JobsProvider")
  return c
}
