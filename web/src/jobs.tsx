import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react"
import { api, type EnrichJob, type PwnedJob } from "./api"
import { useAuth } from "./auth"

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
  const isLead = me?.role === "lead"
  const [enrich, setEnrich] = useState<EnrichJob | null>(null)
  const [hibp, setHibp] = useState<PwnedJob | null>(null)
  const [tick, setTick] = useState(0)
  const refresh = () => setTick((t) => t + 1)

  const anyRunning = computeAnyRunning(enrich, hibp)
  const runningRef = useRef(anyRunning)
  runningRef.current = anyRunning

  useEffect(() => {
    if (!isLead) {
      setEnrich(null)
      setHibp(null)
      return
    }
    let alive = true
    let timer: number | undefined
    const poll = async () => {
      try {
        const [e, h] = await Promise.all([api.enrichJob(), api.pwnedJob()])
        if (!alive) return
        setEnrich(e)
        setHibp(h)
      } catch {
        /* transient (locked/network): keep last state */
      }
      if (!alive) return
      timer = window.setTimeout(poll, runningRef.current ? 1500 : 5000)
    }
    void poll()
    return () => {
      alive = false
      if (timer) window.clearTimeout(timer)
    }
  }, [isLead, tick])

  return <Ctx.Provider value={{ enrich, hibp, anyRunning, refresh }}>{children}</Ctx.Provider>
}

export function useJobs(): JobsState {
  const c = useContext(Ctx)
  if (!c) throw new Error("useJobs must be used within JobsProvider")
  return c
}
