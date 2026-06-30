import { createContext, useContext, useEffect, useState, type ReactNode } from "react"
import { api } from "./api"
import { useAudits } from "./auditsData"
import type { MetricsBundle } from "./metricsBundle"

interface MetricsState { bundle: MetricsBundle | null; loading: boolean; error: string | null }
const MetricsContext = createContext<MetricsState | null>(null)

// MetricsProvider fetches the org /api/metrics bundle once per active audit
// (keyed on activeId + dataVersion, same as AccountsProvider), so every dashboard
// surface can render the single server-computed copy instead of recomputing.
export function MetricsProvider({ children }: { children: ReactNode }) {
  const { activeId, dataVersion } = useAudits()
  const [state, setState] = useState<MetricsState>({ bundle: null, loading: false, error: null })
  useEffect(() => {
    if (!activeId) {
      setState({ bundle: null, loading: false, error: null })
      return
    }
    let alive = true
    setState((s) => ({ ...s, loading: true, error: null }))
    api
      .metrics()
      .then((b) => alive && setState({ bundle: b, loading: false, error: null }))
      .catch((e) => alive && setState({ bundle: null, loading: false, error: String(e) }))
    return () => {
      alive = false
    }
  }, [activeId, dataVersion])
  return <MetricsContext.Provider value={state}>{children}</MetricsContext.Provider>
}

export function useMetrics(): MetricsState {
  const c = useContext(MetricsContext)
  if (!c) throw new Error("useMetrics must be used within MetricsProvider")
  return c
}
