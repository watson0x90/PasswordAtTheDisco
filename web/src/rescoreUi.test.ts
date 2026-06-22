import { describe, expect, it } from "vitest"
import type { IngestEvent } from "./api"
import { lastRecalculatedLabel, recalcDisabledReason, shouldSuggestReenrich } from "./rescoreUi"

// Build a minimal "rescore" ingest event; only `kind` and `at` are read by the
// helpers under test, so the rest are filled with throwaway values.
function rescoreEvent(at: string): IngestEvent {
  return { filename: "", kind: "rescore", accounts_loaded: 0, at, by: "system" } as IngestEvent
}

describe("shouldSuggestReenrich", () => {
  it("is true only for the done phase", () => {
    expect(shouldSuggestReenrich("done")).toBe(true)
  })
  it("is false for every non-done phase", () => {
    expect(shouldSuggestReenrich("running")).toBe(false)
    expect(shouldSuggestReenrich("idle")).toBe(false)
    expect(shouldSuggestReenrich("failed")).toBe(false)
    expect(shouldSuggestReenrich("cancelled")).toBe(false)
    expect(shouldSuggestReenrich(undefined)).toBe(false)
  })
})

describe("lastRecalculatedLabel", () => {
  it("returns '' for null", () => {
    expect(lastRecalculatedLabel(null)).toBe("")
  })
  it("returns '' for an empty list", () => {
    expect(lastRecalculatedLabel([])).toBe("")
  })
  it("returns '' when there are no rescore events", () => {
    const evs: IngestEvent[] = [
      { filename: "x", kind: "dump", at: "2026-06-20T10:00:00.000Z", by: "lead" } as IngestEvent,
    ]
    expect(lastRecalculatedLabel(evs)).toBe("")
  })
  it("picks the latest of multiple rescore events", () => {
    const earlier = "2026-06-20T10:00:00.000Z"
    const later = "2026-06-21T15:30:00.000Z"
    // Intentionally out of order to prove it compares timestamps, not position.
    const label = lastRecalculatedLabel([rescoreEvent(later), rescoreEvent(earlier)])
    expect(label).toContain("Last recalculated")
    expect(label).toContain(new Date(later).toLocaleString())
    expect(label).not.toContain(new Date(earlier).toLocaleString())
  })
})

describe("recalcDisabledReason", () => {
  it("blocks when there is no scored data", () => {
    expect(recalcDisabledReason({ hasScored: false, anyRunning: false })).toBe(
      "No scored data yet — upload a dump first",
    )
  })
  it("blocks when another job is running", () => {
    expect(recalcDisabledReason({ hasScored: true, anyRunning: true })).toBe(
      "Another job is running — wait for it to finish",
    )
  })
  it("allows a recalc when scored and idle", () => {
    expect(recalcDisabledReason({ hasScored: true, anyRunning: false })).toBe("")
  })
})
