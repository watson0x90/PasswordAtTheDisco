import { useEffect, useMemo, useState } from "react"

export type SortDir = "asc" | "desc"

// A sortable column: how to extract a comparable primitive from a row, and the
// natural starting direction when this column is first clicked (text -> asc,
// numbers -> typically "desc" so callers pass defaultDir: "desc").
export interface SortColumn<T> {
  key: string
  get: (row: T) => string | number | boolean | null | undefined
  defaultDir?: SortDir
}

export interface SortState {
  key: string
  dir: SortDir
}

type Primitive = string | number | boolean | null | undefined

// Type-aware compare for non-null values. Numbers numerically, booleans
// false<true, everything else by localeCompare. Always ascending; the caller
// applies direction. null/undefined are handled by sortRows (always last).
export function compareValues(a: Primitive, b: Primitive): number {
  if (typeof a === "number" && typeof b === "number") return a - b
  if (typeof a === "boolean" && typeof b === "boolean") return a === b ? 0 : a ? 1 : -1
  return String(a).localeCompare(String(b))
}

// Stable, direction-aware sort. null/undefined sort LAST regardless of dir.
export function sortRows<T>(rows: T[], col: SortColumn<T> | undefined, dir: SortDir): T[] {
  if (!col) return rows
  const decorated = rows.map((row, i) => ({ row, i, v: col.get(row) }))
  decorated.sort((x, y) => {
    const xn = x.v === null || x.v === undefined
    const yn = y.v === null || y.v === undefined
    if (xn || yn) {
      if (xn && yn) return x.i - y.i
      return xn ? 1 : -1 // nulls last in both directions
    }
    const c = compareValues(x.v, y.v)
    if (c !== 0) return dir === "asc" ? c : -c
    return x.i - y.i // stable
  })
  return decorated.map((d) => d.row)
}

export interface Pagination {
  page: number
  pageSize: number
  total: number
  pageCount: number
  start: number // 1-based index of first shown row (0 when empty)
  end: number // 1-based index of last shown row
}

// Pure page math + slice. Clamps page into [1, pageCount].
export function paginate<T>(rows: T[], page: number, pageSize: number): { slice: T[]; info: Pagination } {
  const total = rows.length
  const pageCount = Math.max(1, Math.ceil(total / pageSize))
  const clamped = Math.min(Math.max(1, page), pageCount)
  const from = (clamped - 1) * pageSize
  const slice = rows.slice(from, from + pageSize)
  return {
    slice,
    info: { page: clamped, pageSize, total, pageCount, start: total === 0 ? 0 : from + 1, end: from + slice.length },
  }
}

// Page-number strip: current ±2, with first/last anchors and "…" gaps.
export function pageWindow(current: number, pageCount: number): (number | "…")[] {
  if (pageCount <= 7) return Array.from({ length: pageCount }, (_, i) => i + 1)
  const out: (number | "…")[] = [1]
  const lo = Math.max(2, current - 2)
  const hi = Math.min(pageCount - 1, current + 2)
  if (lo > 2) out.push("…")
  for (let p = lo; p <= hi; p++) out.push(p)
  if (hi < pageCount - 1) out.push("…")
  out.push(pageCount)
  return out
}

export interface Page<T> extends Pagination {
  rows: T[]
  sort: SortState
  setSort: (key: string) => void
  setPage: (p: number) => void
  setPageSize: (n: number) => void
}

// useSortablePaged: sort + paginate an already-filtered row set. State is local
// to the calling component. Page resets to 1 when the input identity changes,
// when the sort changes, or when the page size changes.
export function useSortablePaged<T>(
  rows: T[],
  cols: SortColumn<T>[],
  opts: { defaultSort: SortState; pageSize?: number },
): Page<T> {
  const [sort, setSortState] = useState<SortState>(opts.defaultSort)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSizeState] = useState(opts.pageSize ?? 50)

  useEffect(() => {
    setPage(1)
  }, [rows])

  const col = cols.find((c) => c.key === sort.key)
  const sorted = useMemo(() => sortRows(rows, col, sort.dir), [rows, col, sort.dir])
  const { slice, info } = useMemo(() => paginate(sorted, page, pageSize), [sorted, page, pageSize])

  function setSort(key: string) {
    setSortState((prev) => {
      if (prev.key === key) return { key, dir: prev.dir === "asc" ? "desc" : "asc" }
      const c = cols.find((x) => x.key === key)
      return { key, dir: c?.defaultDir ?? "asc" }
    })
    setPage(1)
  }
  function setPageSize(n: number) {
    setPageSizeState(n)
    setPage(1)
  }

  return { rows: slice, sort, setSort, setPage, setPageSize, ...info }
}
