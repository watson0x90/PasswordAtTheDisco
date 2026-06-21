import type { CSSProperties, ReactNode } from "react"
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from "recharts"
import type { AxisFactor, Bar as BarDatum, Series, Slice, TierFactorBars } from "../insights"
import {
  IMPACT_COLS,
  IMPACT_UNKNOWN,
  TIERS,
  matrixMaxCount,
  type ExposureImpactMatrix,
  type ImpactCol,
} from "../matrix"

const AXIS = { fill: "#8a96b2", fontSize: 11 }
const TOOLTIP = {
  contentStyle: { background: "#121a2e", border: "1px solid #242e46", borderRadius: 8, fontSize: 12 },
  itemStyle: { color: "#e8edf7" },
  labelStyle: { color: "#8a96b2" },
}

// Donut with a custom legend underneath.
export function Donut({ data, height = 200 }: { data: Slice[]; height?: number }) {
  const total = data.reduce((s, d) => s + d.value, 0)
  return (
    <div>
      <ResponsiveContainer width="100%" height={height}>
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" innerRadius="62%" outerRadius="86%" paddingAngle={2} stroke="none">
            {data.map((d, i) => (
              <Cell key={i} fill={d.color} />
            ))}
          </Pie>
          <Tooltip {...TOOLTIP} />
        </PieChart>
      </ResponsiveContainer>
      <div className="chart-legend">
        {data.map((d) => (
          <span key={d.name} className="chart-legend-item">
            <span className="chart-legend-dot" style={{ background: d.color }} />
            {d.name}
            <b>
              {d.value.toLocaleString()}
              {total ? ` · ${Math.round((d.value / total) * 100)}%` : ""}
            </b>
          </span>
        ))}
      </div>
    </div>
  )
}

// ChartCard is the standard titled panel wrapper used across the chart views.
export function ChartCard({ title, summary, children }: { title: string; summary?: string; children: ReactNode }) {
  return (
    <div className="panel chart-card">
      <div className="chart-title">{title}</div>
      <div role="img" aria-label={summary ? `${title}: ${summary}` : title}>{children}</div>
    </div>
  )
}

// HBars: horizontal bars, good for many/long category labels (complexity, domains).
// Note: recharts measures category-label widths by briefly rendering a hidden
// <span> at top:-20000px (a direct child of <body>). It's off-screen and
// invisible — a known recharts measurement artifact, not a leak; don't chase it.
export function HBars({ data, color = "#38bdf8" }: { data: BarDatum[]; color?: string }) {
  const height = Math.max(120, data.length * 30 + 30)
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 4 }}>
        <XAxis type="number" tick={AXIS} tickLine={false} axisLine={false} allowDecimals={false} />
        <YAxis type="category" dataKey="name" tick={AXIS} tickLine={false} axisLine={false} width={150} />
        <Tooltip {...TOOLTIP} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
        <Bar dataKey="value" fill={color} radius={[0, 4, 4, 0]} maxBarSize={20} />
      </BarChart>
    </ResponsiveContainer>
  )
}

function fmtMag(n: number): string {
  if (n >= 1e6) return `${Math.round(n / 1e6)}M`
  if (n >= 1e3) return `${Math.round(n / 1e3)}k`
  return `${Math.round(n)}`
}

// ScatterPlot: one series per group, x is a log10 magnitude (formatted back to count).
export function ScatterPlot({ series, xLabel }: { series: Series[]; xLabel?: string }) {
  return (
    <div>
      <ResponsiveContainer width="100%" height={250}>
        <ScatterChart margin={{ top: 8, right: 14, left: -12, bottom: 16 }}>
          <XAxis
            type="number"
            dataKey="x"
            tick={AXIS}
            tickLine={false}
            axisLine={{ stroke: "#242e46" }}
            domain={[0, "dataMax"]}
            tickFormatter={(v: number) => fmtMag(Math.pow(10, v) - 1)}
            label={xLabel ? { value: xLabel, position: "insideBottom", offset: -8, fill: "#566076", fontSize: 11 } : undefined}
          />
          <YAxis type="number" dataKey="y" tick={AXIS} tickLine={false} axisLine={false} domain={[0, 10]} width={34} />
          <ZAxis range={[40, 40]} />
          <Tooltip {...TOOLTIP} cursor={{ stroke: "#242e46" }} formatter={(v, n) => (n === "x" ? fmtMag(Math.pow(10, Number(v)) - 1) : v)} />
          {series.map((s) => (
            <Scatter key={s.name} name={s.name} data={s.points} fill={s.color} fillOpacity={0.75} />
          ))}
        </ScatterChart>
      </ResponsiveContainer>
      <div className="chart-legend">
        {series.map((s) => (
          <span key={s.name} className="chart-legend-item">
            <span className="chart-legend-dot" style={{ background: s.color }} />
            {s.name}
          </span>
        ))}
      </div>
    </div>
  )
}

export function Bars({ data, color = "#38bdf8", height = 220 }: { data: BarDatum[]; color?: string; height?: number }) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
        <XAxis dataKey="name" tick={AXIS} tickLine={false} axisLine={{ stroke: "#242e46" }} />
        <YAxis tick={AXIS} tickLine={false} axisLine={false} allowDecimals={false} width={36} />
        <Tooltip {...TOOLTIP} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
        <Bar dataKey="value" fill={color} radius={[4, 4, 0, 0]} maxBarSize={56} />
      </BarChart>
    </ResponsiveContainer>
  )
}

// AxisGroup: one labelled cluster of horizontal sub-score bars (reuses the HBars
// recharts pattern). When muted, factor fills are desaturated to a single grey so the
// chart never implies a real Impact reading for a tier with no enriched accounts.
function AxisGroup({ label, factors, muted = false }: { label: string; factors: AxisFactor[]; muted?: boolean }) {
  const height = factors.length * 26 + 8
  return (
    <div className={`axis-group${muted ? " axis-group-muted" : ""}`}>
      <div className="axis-group-label">{label}</div>
      <ResponsiveContainer width="100%" height={height}>
        <BarChart data={factors} layout="vertical" margin={{ top: 0, right: 22, left: 0, bottom: 0 }}>
          <XAxis type="number" domain={[0, 10]} tick={AXIS} tickLine={false} axisLine={false} allowDecimals={false} hide />
          <YAxis type="category" dataKey="name" tick={AXIS} tickLine={false} axisLine={false} width={84} />
          <Tooltip {...TOOLTIP} cursor={{ fill: "rgba(255,255,255,0.04)" }} formatter={(v) => Number(v).toFixed(2)} />
          <Bar dataKey="value" radius={[0, 3, 3, 0]} maxBarSize={14} isAnimationActive={false}>
            {factors.map((f, i) => (
              <Cell key={i} fill={muted ? "#3a445e" : f.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

// AxisFactorBars: per-tier small multiples of the v2 breakdown sub-scores. Each tier
// card pairs an Exposure cluster (always shown) with an Impact cluster (greyed + a
// caption when no account in the tier was BloodHound-enriched). Replaces the v1 radar.
export function AxisFactorBars({ data }: { data: TierFactorBars[] }) {
  return (
    <div className="axis-bars">
      {data.map((t) => (
        <div key={t.tier} className="axis-tier">
          <div className="axis-tier-head">
            <span className="chart-legend-dot" style={{ background: t.color }} />
            <span className="axis-tier-name">{t.tier}</span>
          </div>
          <div className="axis-tier-body">
            <AxisGroup label="Exposure" factors={t.exposure} />
            <AxisGroup label="Impact" factors={t.impact} muted={!t.impactKnown} />
          </div>
          {!t.impactKnown && <div className="axis-impact-unknown">Impact unknown for this tier — no BloodHound-enriched accounts.</div>}
        </div>
      ))}
    </div>
  )
}

// Per-tier accent used to tint a cell by its IMPACT column (the column tells you the
// blast radius). The Unknown column gets a neutral slate — "we don't know the blast
// radius", deliberately NOT a low/green tone that would read as "safe".
const IMPACT_COL_COLOR: Record<ImpactCol, string> = {
  Critical: "#fb7185",
  High: "#fbbf24",
  Medium: "#a3e635",
  Low: "#22d3ee",
  [IMPACT_UNKNOWN]: "#8a96b2",
}

// MatrixHeatmap: a CSS-grid heatmap of the Exposure × Impact account distribution.
// Rows = Exposure tier (Critical→Low, top-down), columns = Impact tier + an explicit
// "Unknown" column (impact_known=false accounts that can't be placed in an Impact
// tier). Cell tint intensity scales with the account count via a computed --cell
// custom property (count/maxCount); empty cells render muted. The Unknown column is
// set apart with the matrix-col-unknown class so it never reads as "low impact".
export function MatrixHeatmap({ m }: { m: ExposureImpactMatrix }) {
  const maxN = matrixMaxCount(m)
  return (
    <div className="matrix-heatmap" role="table" aria-label="Exposure by Impact account distribution">
      <div className="matrix-axis-y">Exposure ↓</div>
      <div className="matrix-grid" role="rowgroup">
        <div className="matrix-row matrix-row-head" role="row">
          <div className="matrix-corner" role="columnheader">
            <span className="matrix-corner-imp">Impact →</span>
          </div>
          {IMPACT_COLS.map((c) => (
            <div
              key={c}
              role="columnheader"
              className={`matrix-col-head${c === IMPACT_UNKNOWN ? " matrix-col-unknown" : ""}`}
            >
              {c}
            </div>
          ))}
        </div>
        {TIERS.map((exp) => (
          <div key={exp} className="matrix-row" role="row">
            <div className="matrix-row-head-cell" role="rowheader">
              {exp}
            </div>
            {IMPACT_COLS.map((imp) => {
              const n = m.cell(exp, imp)
              const intensity = maxN > 0 ? n / maxN : 0
              const unknown = imp === IMPACT_UNKNOWN
              return (
                <div
                  key={imp}
                  role="cell"
                  className={`matrix-cell${n === 0 ? " matrix-cell-empty" : ""}${unknown ? " matrix-col-unknown" : ""}`}
                  style={{ "--cell": intensity, "--cell-color": IMPACT_COL_COLOR[imp] } as CSSProperties}
                  title={`Exposure ${exp} × Impact ${imp}: ${n} account${n === 1 ? "" : "s"}`}
                >
                  {n}
                </div>
              )
            })}
          </div>
        ))}
      </div>
    </div>
  )
}

// Half-circle posture gauge with the score + rating overlaid in the centre.
export function PostureGauge({ score, color, rating }: { score: number; color: string; rating: string }) {
  return (
    <div className="gauge">
      <ResponsiveContainer width="100%" height={180}>
        <RadialBarChart data={[{ value: score }]} startAngle={210} endAngle={-30} innerRadius="72%" outerRadius="100%">
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
          <RadialBar dataKey="value" cornerRadius={10} fill={color} background={{ fill: "rgba(255,255,255,0.06)" }} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="gauge-center">
        <div className="gauge-score" style={{ color }}>
          {score}
        </div>
        <div className="gauge-rating" style={{ color }}>
          {rating}
        </div>
        <div className="gauge-of">of 100</div>
      </div>
    </div>
  )
}

export interface RadarDatum {
  factor: string
  value: number
}

export interface RadarSeries {
  name: string
  color: string
  data: RadarDatum[]
}

// RiskRadar: radar chart showing average factor contribution by risk tier.
export function RiskRadar({ series }: { series: RadarSeries[] }) {
  if (!series.length) return null
  // Merge all factor names (should be identical across series)
  const factors = series[0].data.map((d) => d.factor)
  // Build a combined data array: [{factor, Critical, High, ...}]
  const combined = factors.map((f) => {
    const row: Record<string, string | number> = { factor: f }
    for (const s of series) {
      const match = s.data.find((d) => d.factor === f)
      row[s.name] = match?.value ?? 0
    }
    return row
  })
  return (
    <div>
      <ResponsiveContainer width="100%" height={280}>
        <RadarChart data={combined} outerRadius="78%">
          <PolarGrid stroke="#242e46" />
          <PolarAngleAxis dataKey="factor" tick={{ fill: "#8a96b2", fontSize: 11 }} />
          <PolarRadiusAxis tick={false} axisLine={false} domain={[0, 10]} />
          {series.map((s) => (
            <Radar key={s.name} name={s.name} dataKey={s.name} stroke={s.color} fill={s.color} fillOpacity={0.15} />
          ))}
          <Tooltip {...TOOLTIP} />
        </RadarChart>
      </ResponsiveContainer>
      <div className="chart-legend">
        {series.map((s) => (
          <span key={s.name} className="chart-legend-item">
            <span className="chart-legend-dot" style={{ background: s.color }} />
            {s.name}
          </span>
        ))}
      </div>
    </div>
  )
}
