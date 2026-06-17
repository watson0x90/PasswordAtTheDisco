import { describe, it, expect } from "vitest"
import { hibpRunning, computeAnyRunning } from "./jobs"
import type { EnrichJob, PwnedJob } from "./api"

const ej = (phase: string): EnrichJob => ({ phase: phase as EnrichJob["phase"], processed: 0, total: 0, enriched: 0, elapsed_sec: 0 })
const pj = (phase: string): PwnedJob => ({ phase: phase as PwnedJob["phase"], resume: false, elapsed_sec: 0, bytes_now: 0, est_total: 0, rate_bps: 0, index_scanned: 0, index_entries: 0, data_file: "" })

describe("jobs derivations", () => {
  it("hibpRunning true only for downloading/indexing", () => {
    expect(hibpRunning("downloading")).toBe(true)
    expect(hibpRunning("indexing")).toBe(true)
    expect(hibpRunning("idle")).toBe(false)
    expect(hibpRunning(undefined)).toBe(false)
  })
  it("computeAnyRunning across enrich + hibp", () => {
    expect(computeAnyRunning(null, null)).toBe(false)
    expect(computeAnyRunning(ej("running"), pj("idle"))).toBe(true)
    expect(computeAnyRunning(ej("done"), pj("indexing"))).toBe(true)
    expect(computeAnyRunning(ej("done"), pj("done"))).toBe(false)
  })
})
