import { describe, it, expect } from "vitest"
import { toBars } from "./components/BarChart"

describe("toBars", () => {
  it("scales widths to the max and preserves order", () => {
    const bars = toBars([
      { label: "Forbidden", n: 6 },
      { label: "Common", n: 3 },
      { label: "Keyboard", n: 0 },
    ])
    expect(bars[0]).toEqual({ label: "Forbidden", n: 6, pct: 100 })
    expect(bars[1].pct).toBe(50)
    expect(bars[2].pct).toBe(0)
  })

  it("handles all-zero without dividing by zero", () => {
    const bars = toBars([{ label: "X", n: 0 }])
    expect(bars[0].pct).toBe(0)
  })
})
