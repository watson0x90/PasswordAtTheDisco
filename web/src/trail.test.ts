import { describe, expect, it } from "vitest"
import { type Crumb, pushCrumb, popCrumb, jumpCrumb } from "./trail"

const a: Crumb = { username: "alice", domain: "CORP" }
const b: Crumb = { username: "bob", domain: "CORP" }

describe("trail reducer", () => {
  it("pushes a new crumb", () => {
    expect(pushCrumb([a], b)).toEqual([a, b])
  })
  it("ignores a consecutive duplicate of the tail", () => {
    expect(pushCrumb([a, b], { ...b })).toEqual([a, b])
  })
  it("pops the last crumb but never below depth 1", () => {
    expect(popCrumb([a, b])).toEqual([a])
    expect(popCrumb([a])).toEqual([a])
  })
  it("jumps to a depth, truncating deeper crumbs", () => {
    expect(jumpCrumb([a, b], 0)).toEqual([a])
    expect(jumpCrumb([a, b], 5)).toEqual([a, b]) // out of range = no-op
  })
})
