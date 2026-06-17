import { describe, it, expect } from "vitest"
import { tableWindow } from "./components/AccountsTable"

describe("tableWindow", () => {
  it("renders all rows below the virtualization threshold", () => {
    expect(tableWindow(50, 0, 560)).toEqual({ virtual: false, start: 0, end: 50 })
  })
  it("windows rows above the threshold", () => {
    const w = tableWindow(10000, 3800, 560) // ROW_H=38, OVERSCAN=10
    expect(w.virtual).toBe(true)
    expect(w.start).toBe(90)  // floor(3800/38)=100, -10 overscan
    expect(w.end).toBe(125)   // ceil((3800+560)/38)=115, +10 overscan
    expect(w.start).toBeLessThan(w.end)
  })
})
