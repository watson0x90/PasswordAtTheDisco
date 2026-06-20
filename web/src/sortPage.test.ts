import { describe, it, expect } from "vitest"
import { compareValues, sortRows, paginate, pageWindow, type SortColumn } from "./sortPage"

describe("compareValues", () => {
  it("orders numbers numerically", () => {
    expect(compareValues(2, 10)).toBeLessThan(0)
    expect(compareValues(10, 2)).toBeGreaterThan(0)
    expect(compareValues(5, 5)).toBe(0)
  })
  it("orders strings via localeCompare", () => {
    expect(compareValues("apple", "banana")).toBeLessThan(0)
  })
  it("orders booleans false < true", () => {
    expect(compareValues(false, true)).toBeLessThan(0)
  })
})

interface Row { name: string; n: number; risk: number | null }
const rows: Row[] = [
  { name: "charlie", n: 3, risk: 2 },
  { name: "alice", n: 1, risk: null },
  { name: "bob", n: 2, risk: 4 },
]
const nameCol: SortColumn<Row> = { key: "name", get: (r) => r.name }
const nCol: SortColumn<Row> = { key: "n", get: (r) => r.n }
const riskCol: SortColumn<Row> = { key: "risk", get: (r) => r.risk }

describe("sortRows", () => {
  it("sorts ascending by string", () => {
    expect(sortRows(rows, nameCol, "asc").map((r) => r.name)).toEqual(["alice", "bob", "charlie"])
  })
  it("sorts descending by number", () => {
    expect(sortRows(rows, nCol, "desc").map((r) => r.n)).toEqual([3, 2, 1])
  })
  it("puts null last in BOTH directions", () => {
    expect(sortRows(rows, riskCol, "asc").map((r) => r.risk)).toEqual([2, 4, null])
    expect(sortRows(rows, riskCol, "desc").map((r) => r.risk)).toEqual([4, 2, null])
  })
  it("is stable for equal keys (preserves input order)", () => {
    const eq: Row[] = [
      { name: "x", n: 1, risk: 1 },
      { name: "y", n: 1, risk: 1 },
      { name: "z", n: 1, risk: 1 },
    ]
    expect(sortRows(eq, nCol, "asc").map((r) => r.name)).toEqual(["x", "y", "z"])
  })
  it("returns rows unchanged when column is undefined", () => {
    expect(sortRows(rows, undefined, "asc")).toEqual(rows)
  })
})

describe("paginate", () => {
  const data = Array.from({ length: 23 }, (_, i) => i + 1)
  it("slices the right page", () => {
    const { slice, info } = paginate(data, 2, 10)
    expect(slice).toEqual([11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
    expect(info).toMatchObject({ page: 2, pageCount: 3, total: 23, start: 11, end: 20 })
  })
  it("clamps an out-of-range page to the last page", () => {
    const { info } = paginate(data, 99, 10)
    expect(info.page).toBe(3)
    expect(info.start).toBe(21)
    expect(info.end).toBe(23)
  })
  it("handles an empty list", () => {
    const { slice, info } = paginate([], 1, 10)
    expect(slice).toEqual([])
    expect(info).toMatchObject({ page: 1, pageCount: 1, total: 0, start: 0, end: 0 })
  })
})

describe("pageWindow", () => {
  it("lists all pages when few", () => {
    expect(pageWindow(1, 5)).toEqual([1, 2, 3, 4, 5])
  })
  it("windows with gaps around the current page", () => {
    expect(pageWindow(6, 20)).toEqual([1, "…", 4, 5, 6, 7, 8, "…", 20])
  })
  it("no leading gap near the start", () => {
    expect(pageWindow(2, 20)).toEqual([1, 2, 3, 4, "…", 20])
  })
})
