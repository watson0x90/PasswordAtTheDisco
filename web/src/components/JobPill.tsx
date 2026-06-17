import { useState, useRef, useEffect } from "react"
import { api, ApiError, type EnrichJob, type PwnedJob } from "../api"
import { useAuth } from "../auth"
import { useJobs } from "../jobs"

// jobPillLabel renders the compact pill text for the current job state ("" = hide).
export function jobPillLabel(enrich: EnrichJob | null, hibp: PwnedJob | null): string {
  const e = enrich?.phase === "running"
  const h = hibp?.phase === "downloading" || hibp?.phase === "indexing"
  if (e && h) return "2 jobs"
  if (e) return `Enriching… ${enrich!.processed}/${enrich!.total}`
  if (h) return `HIBP ${hibp!.phase}…`
  return ""
}

export function JobPill() {
  const { me } = useAuth()
  const { enrich, hibp, anyRunning } = useJobs()
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
  const label = jobPillLabel(enrich, hibp)

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

  return (
    <div className="jobpill-wrap" ref={wrapRef}>
      <button className="jobpill" onClick={() => setOpen((o) => !o)} title="Background jobs">
        <span className="spin">⟳</span> {label}
      </button>
      {open && (
        <div className="jobpop" role="menu" aria-label="Background jobs">
          {enrichRunning && (
            <div className="jobpop-row">
              <span>BloodHound enrichment — {enrich!.processed}/{enrich!.total} ({enrich!.enriched} enriched)</span>
              <button className="link-btn" onClick={() => void cancelEnrich()}>cancel</button>
            </div>
          )}
          {hibpRunning && (
            <div className="jobpop-row">
              <span>HIBP corpus — {hibp!.phase}</span>
              <button className="link-btn" onClick={() => void cancelHibp()}>cancel</button>
            </div>
          )}
          {err && <div className="error">{err}</div>}
        </div>
      )}
    </div>
  )
}
