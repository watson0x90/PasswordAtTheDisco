import { describe, it, expect } from "vitest"
import { MetricsProvider, useMetrics } from "./metricsData"

describe("metricsData exports", () => {
  it("exposes the provider and hook", () => {
    expect(typeof MetricsProvider).toBe("function")
    expect(typeof useMetrics).toBe("function")
  })
})
