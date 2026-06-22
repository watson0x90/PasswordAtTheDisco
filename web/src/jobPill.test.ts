import { describe, it, expect } from "vitest"
import { jobPillLabel } from "./components/JobPill"
import type { EnrichJob, PwnedJob, RescoreJob } from "./api"

const ej = (phase: string, processed = 0, total = 0): EnrichJob => ({ phase: phase as EnrichJob["phase"], processed, total, enriched: 0, elapsed_sec: 0 })
const pj = (phase: string): PwnedJob => ({ phase: phase as PwnedJob["phase"], resume: false, elapsed_sec: 0, bytes_now: 0, est_total: 0, rate_bps: 0, index_scanned: 0, index_entries: 0, data_file: "" })
const rj = (phase: string, processed = 0, total = 0): RescoreJob => ({ phase: phase as RescoreJob["phase"], processed, total, elapsed_sec: 0 })

describe("jobPillLabel", () => {
  it("empty when nothing runs", () => { expect(jobPillLabel(ej("idle"), pj("idle"), rj("idle"))).toBe("") })
  it("enrichment progress", () => { expect(jobPillLabel(ej("running", 42, 120), pj("idle"), rj("idle"))).toBe("Enriching… 42/120") })
  it("HIBP phase", () => { expect(jobPillLabel(ej("idle"), pj("indexing"), rj("idle"))).toBe("HIBP indexing…") })
  it("rescore progress", () => { expect(jobPillLabel(ej("idle"), pj("idle"), rj("running", 7, 50))).toBe("Recalculating… 7/50") })
  it("two running -> 2 jobs", () => { expect(jobPillLabel(ej("running", 1, 2), pj("downloading"), rj("idle"))).toBe("2 jobs") })
  it("three running -> 3 jobs", () => { expect(jobPillLabel(ej("running", 1, 2), pj("downloading"), rj("running", 3, 4))).toBe("3 jobs") })
  it("tolerates null jobs (the real initial state)", () => {
    expect(jobPillLabel(null, null, null)).toBe("")
    expect(jobPillLabel(ej("running", 1, 2), null, null)).toBe("Enriching… 1/2")
    expect(jobPillLabel(null, null, rj("running", 5, 9))).toBe("Recalculating… 5/9")
  })
})
