import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { api, type EnrichJob, type PwnedJob, type RescoreJob } from "./api"
import { useAuth } from "./auth"
import { useAudits } from "./auditsData"

interface JobsState {
  enrich: EnrichJob | null
  hibp: PwnedJob | null
  rescore: RescoreJob | null
  anyRunning: boolean
  refresh: () => void
}

const Ctx = createContext<JobsState | null>(null)

// hibpRunning reports whether the HIBP corpus job is mid-flight.
export const hibpRunning = (p?: string) => p === "downloading" || p === "indexing"

// computeAnyRunning is true when any background job is in progress.
export function computeAnyRunning(enrich: EnrichJob | null, hibp: PwnedJob | null, rescore: RescoreJob | null): boolean {
  return enrich?.phase === "running" || hibpRunning(hibp?.phase) || rescore?.phase === "running"
}

// JobsProvider polls the three background-job endpoints (BloodHound enrichment,
// HIBP download/index, and re-scoring) and shares their state. All are lead-only,
// so it polls only for leads. Cadence: 5s idle, 1.5s while a job runs.
export function JobsProvider({ children }: { children: ReactNode }) {
  const { me } = useAuth()
  const { bumpData } = useAudits()
  const isLead = me?.role === "lead"
  const [enrich, setEnrich] = useState<EnrichJob | null>(null)
  const [hibp, setHibp] = useState<PwnedJob | null>(null)
  const [rescore, setRescore] = useState<RescoreJob | null>(null)
  const [tick, setTick] = useState(0)
  const refresh = useCallback(() => setTick((t) => t + 1), [])

  const anyRunning = computeAnyRunning(enrich, hibp, rescore)
  const runningRef = useRef(anyRunning)
  runningRef.current = anyRunning

  const prevEnrichPhase = useRef<string | undefined>(undefined)
  useEffect(() => {
    if (prevEnrichPhase.current === "running" && enrich?.phase === "done") bumpData()
    prevEnrichPhase.current = enrich?.phase
  }, [enrich?.phase, bumpData])

  // re-scoring rewrites account scores, so refresh cached account data on completion.
  const prevRescorePhase = useRef<string | undefined>(undefined)
  useEffect(() => {
    if (prevRescorePhase.current === "running" && rescore?.phase === "done") bumpData()
    prevRescorePhase.current = rescore?.phase
  }, [rescore?.phase, bumpData])

  useEffect(() => {
    if (!isLead) {
      setEnrich(null)
      setHibp(null)
      setRescore(null)
      return
    }
    let alive = true
    let timer: number | undefined
    const poll = async () => {
      // allSettled never rejects; a transient error on one endpoint (locked /
      // network) leaves that job's last state intact while the other still updates.
      const [e, h, r] = await Promise.allSettled([api.enrichJob(), api.pwnedJob(), api.rescoreJob()])
      if (!alive) return
      if (e.status === "fulfilled") setEnrich(e.value)
      if (h.status === "fulfilled") setHibp(h.value)
      if (r.status === "fulfilled") setRescore(r.value)
      timer = window.setTimeout(poll, runningRef.current ? 1500 : 5000)
    }
    void poll()
    return () => {
      alive = false
      if (timer) window.clearTimeout(timer)
    }
  }, [isLead, tick])

  const value = useMemo(() => ({ enrich, hibp, rescore, anyRunning, refresh }), [enrich, hibp, rescore, anyRunning, refresh])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useJobs(): JobsState {
  const c = useContext(Ctx)
  if (!c) throw new Error("useJobs must be used within JobsProvider")
  return c
}
