import { useEffect, useState } from "react"
import { useAuth } from "../auth"
import { useJobs } from "../jobs"
import { useNav } from "../nav"
import { shouldSuggestReenrich } from "../rescoreUi"

// RecalcSuggestion shows, after a successful recalc, a prompt to re-run BloodHound
// enrichment (rescore preserves the existing Impact; re-enriching refreshes it).
// Lead-only and dismissable; re-armed whenever a new rescore starts.
export function RecalcSuggestion() {
  const { me } = useAuth()
  const { rescore } = useJobs()
  const nav = useNav()
  const [dismissed, setDismissed] = useState(false)
  const phase = rescore?.phase
  useEffect(() => { if (phase === "running") setDismissed(false) }, [phase])
  if (me?.role !== "lead") return null
  if (!shouldSuggestReenrich(phase) || dismissed) return null
  const n = rescore?.processed ?? 0
  return (
    <div className="coverage-banner" role="status">
      <span className="coverage-banner-dot" aria-hidden="true" />
      <span className="coverage-banner-text">
        <b>Recalculated {n} accounts.</b> BloodHound Impact was preserved — re-run enrichment to refresh it.
      </span>
      <button className="link-btn" onClick={() => nav("integrations")}>Re-run enrichment →</button>
      <button className="link-btn" onClick={() => setDismissed(true)}>dismiss</button>
    </div>
  )
}
