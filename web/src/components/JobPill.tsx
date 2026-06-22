import { useState, useRef, useEffect } from "react"
import { api, ApiError, type EnrichJob, type PwnedJob, type RescoreJob } from "../api"
import { useAuth } from "../auth"
import { useJobs } from "../jobs"

// jobPillLabel renders the compact pill text for the current job state ("" = hide).
export function jobPillLabel(enrich: EnrichJob | null, hibp: PwnedJob | null, rescore: RescoreJob | null): string {
  const e = enrich?.phase === "running"
  const h = hibp?.phase === "downloading" || hibp?.phase === "indexing"
  const r = rescore?.phase === "running"
  const n = (e ? 1 : 0) + (h ? 1 : 0) + (r ? 1 : 0)
  if (n > 1) return `${n} jobs`
  if (e) return `Enriching… ${enrich!.processed}/${enrich!.total}`
  if (h) return `HIBP ${hibp!.phase}…`
  if (r) return `Recalculating… ${rescore!.processed}/${rescore!.total}`
  return ""
}

export function JobPill() {
  const { me } = useAuth()
  const { enrich, hibp, rescore, anyRunning } = useJobs()
  const [open, setOpen] = useState(false)
  const [err, setErr] = useState("")
  const wrapRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => { if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false) }
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false) }
    document.addEventListener("mousedown", onDown)
    document.addEventListener("keydown", onKey)
    return () => { document.removeEventListener("mousedown", onDown); document.removeEventListener("keydown", onKey) }
  }, [open])
  if (!anyRunning) return null

  const enrichRunning = enrich?.phase === "running"
  const hibpRunning = hibp?.phase === "downloading" || hibp?.phase === "indexing"
  const rescoreRunning = rescore?.phase === "running"
  const label = jobPillLabel(enrich, hibp, rescore)

  async function cancelEnrich() {
    if (!me) return
    setErr("")
    try { await api.enrichCancel(me.csrf_token) } catch (e) { setErr(e instanceof ApiError ? e.message : "cancel failed") }
  }
  async function cancelHibp() {
    if (!me) return
    setErr("")
    try { await api.pwnedCancel(me.csrf_token) } catch (e) { setErr(e instanceof ApiError ? e.message : "cancel failed") }
  }
  async function cancelRescore() {
    if (!me) return
    setErr("")
    try { await api.rescoreCancel(me.csrf_token) } catch (e) { setErr(e instanceof ApiError ? e.message : "cancel failed") }
  }

  return (
    <div className="jobpill-wrap" ref={wrapRef}>
      <button className="jobpill" onClick={() => setOpen((o) => !o)} title="Background jobs" aria-haspopup="menu" aria-expanded={open}>
        <span className="spin">⟳</span> {label}
      </button>
      {open && (
        <div className="jobpop" role="menu" aria-label="Background jobs">
          {enrichRunning && (
            <div className="jobpop-row">
              <span>BloodHound enrichment — {enrich!.processed}/{enrich!.total} ({enrich!.enriched} enriched)</span>
              <button className="link-btn" role="menuitem" onClick={() => void cancelEnrich()}>cancel</button>
            </div>
          )}
          {hibpRunning && (
            <div className="jobpop-row">
              <span>HIBP corpus — {hibp!.phase}</span>
              <button className="link-btn" role="menuitem" onClick={() => void cancelHibp()}>cancel</button>
            </div>
          )}
          {rescoreRunning && (
            <div className="jobpop-row">
              <span>Re-scoring — {rescore!.processed}/{rescore!.total} accounts</span>
              <button className="link-btn" role="menuitem" onClick={() => void cancelRescore()}>cancel</button>
            </div>
          )}
          {err && <div className="error">{err}</div>}
        </div>
      )}
    </div>
  )
}
