import type { ReactNode } from "react"
import type { SortState } from "../sortPage"

// A clickable column header. `info` renders after the label (e.g. an <InfoTip>)
// OUTSIDE the button so the tooltip stays independently interactive.
export function SortHeader({
  label,
  colKey,
  sort,
  onSort,
  numeric,
  info,
}: {
  label: string
  colKey: string
  sort: SortState
  onSort: (key: string) => void
  numeric?: boolean
  info?: ReactNode
}) {
  const active = sort.key === colKey
  const indicator = active ? (sort.dir === "asc" ? "▲" : "▼") : "↕"
  return (
    <th className={numeric ? "num" : undefined} aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}>
      <button type="button" className={active ? "th-sort active" : "th-sort"} onClick={() => onSort(colKey)}>
        {label}
        <span className="th-sort-ind">{indicator}</span>
      </button>
      {info}
    </th>
  )
}
