import { useState } from "react"
import { api, ApiError } from "../api"
import { useAuth } from "../auth"
import { useJobs } from "../jobs"
import { recalcNudgeVisible } from "../rescoreUi"

// RecalcNudge prompts a lead to re-score after a scoring-input change (a policy
// edit, a forbidden-words edit, or an HIBP rebuild). `saved` is the editor's
// success signal. Lead-only; hidden until a save succeeds and while a rescore runs.
export function RecalcNudge({ saved }: { saved: boolean }) {
  const { me } = useAuth()
  const { rescore, anyRunning, refresh } = useJobs()
  const [err, setErr] = useState("")
  if (me?.role !== "lead") return null
  if (!recalcNudgeVisible(saved, rescore?.phase === "running")) return null
  const start = async () => {
    if (!me) return
    setErr("")
    try { await api.rescore(me.csrf_token); refresh() }
    catch (e) { setErr(e instanceof ApiError ? e.message : "recalculate failed") }
  }
  return (
    <div className="coverage-banner" role="status">
      <span className="coverage-banner-dot" aria-hidden="true" />
      <span className="coverage-banner-text">
        Updated — <b>recalculate scoring</b> to apply this to existing accounts.
      </span>
      <button className="link-btn" onClick={() => void start()} disabled={anyRunning}>Recalculate scoring →</button>
      {err && <span className="error">{err}</span>}
    </div>
  )
}
