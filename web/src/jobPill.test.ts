import { describe, it, expect } from "vitest"
import { jobPillLabel } from "./components/JobPill"
import type { EnrichJob, PwnedJob } from "./api"

const ej = (phase: string, processed = 0, total = 0): EnrichJob => ({ phase: phase as EnrichJob["phase"], processed, total, enriched: 0, elapsed_sec: 0 })
const pj = (phase: string): PwnedJob => ({ phase: phase as PwnedJob["phase"], resume: false, elapsed_sec: 0, bytes_now: 0, est_total: 0, rate_bps: 0, index_scanned: 0, index_entries: 0, data_file: "" })

describe("jobPillLabel", () => {
  it("empty when nothing runs", () => { expect(jobPillLabel(ej("idle"), pj("idle"))).toBe("") })
  it("enrichment progress", () => { expect(jobPillLabel(ej("running", 42, 120), pj("idle"))).toBe("Enriching… 42/120") })
  it("HIBP phase", () => { expect(jobPillLabel(ej("idle"), pj("indexing"))).toBe("HIBP indexing…") })
  it("both running -> 2 jobs", () => { expect(jobPillLabel(ej("running", 1, 2), pj("downloading"))).toBe("2 jobs") })
})
