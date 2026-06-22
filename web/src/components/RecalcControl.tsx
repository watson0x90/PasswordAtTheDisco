import { useEffect, useState } from "react"
import { api, ApiError, type IngestEvent } from "../api"
import { useAuth } from "../auth"
import { useAudits } from "../auditsData"
import { useJobs } from "../jobs"
import { lastRecalculatedLabel, recalcDisabledReason } from "../rescoreUi"

// RecalcControl renders the lead-only "Recalculate scoring" action plus a
// "Last recalculated" stamp, for the Overview head. hasScored gates the button
// (no scored data => nothing to recompute).
export function RecalcControl({ hasScored }: { hasScored: boolean }) {
  const { me } = useAuth()
  const { activeId } = useAudits()
  const { rescore, anyRunning, refresh } = useJobs()
  const [ingests, setIngests] = useState<IngestEvent[] | null>(null)
  const [err, setErr] = useState("")
  const phase = rescore?.phase
  const running = phase === "running"

  // (Re)load the ingest history when the rescore phase changes (esp. -> done) so
  // the stamp updates right after a run completes, and when the active audit
  // changes so the stamp never lingers from a previously-open audit. Background
  // load: errors are swallowed like Dashboard's summary/report fetches.
  useEffect(() => {
    let alive = true
    api.ingests().then((evs) => { if (alive) setIngests(evs) }).catch(() => {})
    return () => { alive = false }
  }, [phase, activeId])

  if (me?.role !== "lead") return null

  const reason = recalcDisabledReason({ hasScored, anyRunning })
  const label = lastRecalculatedLabel(ingests)
  const start = async () => {
    if (!me) return
    setErr("")
    try { await api.rescore(me.csrf_token); refresh() }
    catch (e) { setErr(e instanceof ApiError ? e.message : "recalculate failed") }
  }
  return (
    <>
      {label && <span className="muted data-ts">{label}</span>}
      <button
        className="btn"
        onClick={() => void start()}
        disabled={!!reason || running}
        title={reason || "Re-score the active audit with current policy, wordlists, and HIBP"}
      >
        {running ? `Recalculating… ${rescore!.processed}/${rescore!.total}` : "Recalculate scoring"}
      </button>
      {err && <span className="error">{err}</span>}
    </>
  )
}
