import { useEffect, useState } from "react"
import { api, ApiError, type Summary } from "../api"

const RISK_ORDER = ["Critical", "High", "Medium", "Low"]
const RISK_CLASS: Record<string, string> = {
  Critical: "crit",
  High: "high",
  Medium: "med",
  Low: "low",
}

export function Dashboard() {
  const [summary, setSummary] = useState<Summary | null>(null)
  const [error, setError] = useState("")

  useEffect(() => {
    api
      .summary()
      .then(setSummary)
      .catch((e) => setError(e instanceof ApiError ? e.message : "failed to load summary"))
  }, [])

  if (error) return <div className="center-state">{error}</div>
  if (!summary) {
    return (
      <div className="center-state">
        <div className="spinner">loading</div>
      </div>
    )
  }

  const crackPct = summary.total_accounts ? Math.round((summary.cracked / summary.total_accounts) * 100) : 0
  const maxRisk = Math.max(1, ...RISK_ORDER.map((r) => summary.risk_counts[r] || 0))

  return (
    <>
      <div className="section-label">Overview</div>
      <div className="stat-grid">
        <Stat label="Accounts" value={summary.total_accounts} delay={0} />
        <Stat label="Cracked" value={summary.cracked} sub={`${crackPct}% of accounts`} delay={0.06} />
        <Stat label="HIBP Breached" value={summary.hibp_breached} accent delay={0.12} />
        <Stat label="DA Pathways" value={summary.da_pathways} crit delay={0.18} />
      </div>

      <div className="section-label">Risk Distribution</div>
      <div className="panel">
        {RISK_ORDER.map((r) => {
          const n = summary.risk_counts[r] || 0
          const cls = RISK_CLASS[r]
          return (
            <div className="risk-row" key={r}>
              <div className="risk-name">
                <span className={`risk-dot bg-${cls}`} />
                {r}
              </div>
              <div className="risk-track">
                <div className={`risk-fill bg-${cls}`} style={{ width: `${(n / maxRisk) * 100}%` }} />
              </div>
              <div className={`risk-count c-${cls}`}>{n.toLocaleString()}</div>
            </div>
          )
        })}
        <div className="meta-line">snapshot generated {fmtTime(summary.generated_at)}</div>
      </div>
    </>
  )
}

interface StatProps {
  label: string
  value: number
  sub?: string
  accent?: boolean
  crit?: boolean
  delay: number
}

function Stat({ label, value, sub, accent, crit, delay }: StatProps) {
  const cls = crit ? "stat crit" : accent ? "stat accent" : "stat"
  return (
    <div className={cls} style={{ animationDelay: `${delay}s` }}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value.toLocaleString()}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}

function fmtTime(iso: string): string {
  const d = new Date(iso)
  return isNaN(d.getTime()) ? iso : d.toLocaleString()
}
