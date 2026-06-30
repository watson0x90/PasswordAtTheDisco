import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { describe, it, expect } from "vitest"
import type { MetricsBundle } from "./metricsBundle"

// The Go golden is the authoritative server output; the TS types must describe it.
const goldenPath = resolve(__dirname, "../../internal/metrics/testdata/metrics_golden.json")

describe("MetricsBundle matches the Go golden", () => {
  it("parses and has the expected top-level + nested shape", () => {
    const raw = JSON.parse(readFileSync(goldenPath, "utf8")) as MetricsBundle
    // top level
    expect(raw.summary).toBeDefined()
    expect(raw.matrix).toBeDefined()
    expect(raw.charts).toBeDefined()
    expect(raw.reports).toBeDefined()
    expect(Array.isArray(raw.domains)).toBe(true)
    // matrix
    expect(typeof raw.matrix.total).toBe("number")
    expect(typeof raw.matrix.max).toBe("number")
    expect(raw.matrix.counts).toBeTruthy()
    // charts (a representative sample of the 18 fields)
    expect(Array.isArray(raw.charts.risk_distribution)).toBe(true)
    expect(Array.isArray(raw.charts.top_riskiest)).toBe(true)
    expect(typeof raw.charts.top_controllers_more_over_100).toBe("number")
    // reports
    expect(raw.reports.exposure_headline).toBeDefined()
    expect(typeof raw.reports.exposure_headline.cracked_da).toBe("number")
    expect(Array.isArray(raw.reports.worklist)).toBe(true)
    expect(raw.reports.reuse_graph).toBeDefined()
    expect(Array.isArray(raw.reports.reuse_graph.nodes)).toBe(true)
    // per-domain
    expect(raw.domains.length).toBeGreaterThan(0)
    expect(raw.domains[0].domain).toBeTypeOf("string")
    expect(raw.domains[0].charts).toBeDefined()
  })
})
