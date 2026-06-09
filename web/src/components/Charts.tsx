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
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"
import type { Bar as BarDatum, Slice } from "../insights"

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
