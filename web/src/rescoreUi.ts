import type { IngestEvent, RescoreJob } from "./api"

// shouldSuggestReenrich: right after a successful rescore, suggest re-running
// BloodHound enrichment so the preserved (possibly-stale) Impact axis is refreshed.
export function shouldSuggestReenrich(phase: RescoreJob["phase"] | undefined): boolean {
  return phase === "done"
}

// lastRescoreAt: ISO timestamp of the most recent "rescore" ingest event, or null.
export function lastRescoreAt(ingests: IngestEvent[] | null | undefined): string | null {
  if (!ingests) return null
  let latest: string | null = null
  for (const e of ingests) {
    if (e.kind !== "rescore") continue
    if (latest === null || new Date(e.at).getTime() > new Date(latest).getTime()) latest = e.at
  }
  return latest
}

// lastRecalculatedLabel: "Last recalculated <local time>", or "" if never.
export function lastRecalculatedLabel(ingests: IngestEvent[] | null | undefined): string {
  const at = lastRescoreAt(ingests)
  return at ? `Last recalculated ${new Date(at).toLocaleString()}` : ""
}

// recalcDisabledReason: "" when a recalc can start, else a short tooltip/disable reason.
export function recalcDisabledReason(opts: { hasScored: boolean; anyRunning: boolean }): string {
  if (!opts.hasScored) return "No scored data yet — upload a dump first"
  if (opts.anyRunning) return "Another job is running — wait for it to finish"
  return ""
}

// recalcNudgeVisible decides whether to show the "recalculate to apply" nudge
// after a scoring-input change (policy/wordlist/HIBP). Visible only after a
// successful save/rebuild, and suppressed while a rescore is already running
// (the RecalcControl/JobPill already surface that).
export function recalcNudgeVisible(saved: boolean, rescoreRunning: boolean): boolean {
  return saved && !rescoreRunning
}
