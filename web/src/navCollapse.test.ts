import { describe, expect, it } from "vitest"
import { nextNavCollapse } from "./navCollapse"

describe("nextNavCollapse", () => {
  const expanded = { collapsed: false, neededWidth: 0 }

  it("stays expanded (same ref) when the content fits", () => {
    expect(nextNavCollapse(expanded, 1200, 1100)).toBe(expanded)
  })

  it("ignores a 1px overflow (tolerance)", () => {
    expect(nextNavCollapse(expanded, 1000, 1001)).toBe(expanded)
  })

  it("collapses when content overflows, remembering the needed width", () => {
    expect(nextNavCollapse(expanded, 900, 1300)).toEqual({ collapsed: true, neededWidth: 1300 })
  })

  it("stays collapsed (same ref) until the bar is wide enough", () => {
    const collapsed = { collapsed: true, neededWidth: 1300 }
    expect(nextNavCollapse(collapsed, 1200, 400)).toBe(collapsed)
  })

  it("expands once the bar reaches the remembered needed width", () => {
    const collapsed = { collapsed: true, neededWidth: 1300 }
    expect(nextNavCollapse(collapsed, 1300, 400)).toEqual({ collapsed: false, neededWidth: 1300 })
  })
})
