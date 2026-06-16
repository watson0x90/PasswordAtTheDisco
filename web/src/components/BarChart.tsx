export interface BarInput {
  label: string
  n: number
}

export interface Bar extends BarInput {
  pct: number
}

// toBars scales each row's width to the largest value (0 when all are zero).
export function toBars(rows: BarInput[]): Bar[] {
  const max = Math.max(1, ...rows.map((r) => r.n))
  return rows.map((r) => ({ ...r, pct: Math.round((r.n / max) * 100) }))
}

// BarChart renders a horizontal CSS bar chart (no chart library).
export function BarChart({ rows, accent }: { rows: BarInput[]; accent?: "term" }) {
  const bars = toBars(rows)
  return (
    <div className={accent === "term" ? "barchart term" : "barchart"}>
      {bars.map((b) => (
        <div className="barrow" key={b.label}>
          <span className="barlabel">{b.label}</span>
          <span className="bartrack">
            <span className="barfill" style={{ width: `${b.pct}%` }} />
          </span>
          <span className="barn">{b.n.toLocaleString()}</span>
        </div>
      ))}
    </div>
  )
}
