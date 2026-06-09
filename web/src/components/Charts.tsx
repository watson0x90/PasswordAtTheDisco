import type { ReactNode } from "react"
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  PolarAngleAxis,
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
import type { Bar as BarDatum, Series, Slice } from "../insights"

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
export function ChartCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="panel chart-card">
      <div className="chart-title">{title}</div>
      {children}
    </div>
  )
}

// HBars: horizontal bars, good for many/long category labels (complexity, domains).
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
