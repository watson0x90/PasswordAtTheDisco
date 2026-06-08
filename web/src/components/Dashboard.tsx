import { useEffect, useState } from "react"
import { api, ApiError, type Summary } from "../api"
import { useAuth } from "../auth"
import { useNav } from "../nav"

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
  if (summary.total_accounts === 0) return <GetStarted />

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

function GetStarted() {
  const { me } = useAuth()
  const nav = useNav()
  const isLead = me?.role === "lead"
  return (
    <>
      <div className="section-label">Get started</div>
      <div className="panel getstarted">
        <h2 className="gs-title">Start a password audit</h2>
        <p className="gs-sub">
          {isLead
            ? "No data ingested yet — follow these steps to run your first audit."
            : "No data ingested yet. A lead needs to upload credential dumps before findings appear."}
        </p>

        <ol className="gs-steps">
          <li className="gs-step">
            <span className="gs-num">1</span>
            <div className="gs-body">
              <div className="gs-head">
                Configure policies <span className="gs-opt">optional</span>
              </div>
              <div className="gs-text">
                Set per-domain password rules (min length, required classes, max age). They drive the
                “Meets Policy” and max-age compliance signals in scoring.
              </div>
            </div>
            {isLead && (
              <button className="btn gs-action" onClick={() => nav("policies")}>
                Open Policies →
              </button>
            )}
          </li>

          <li className="gs-step gs-current">
            <span className="gs-num">2</span>
            <div className="gs-body">
              <div className="gs-head">Upload credential dumps</div>
              <div className="gs-text">
                Upload the cracked (and optional uncracked) files for a domain. The server parses them,
                correlates against HIBP, scores each account, and ingests — cleartext never touches disk.
              </div>
            </div>
            {isLead && (
              <button className="btn btn-primary gs-action" onClick={() => nav("ingest")}>
                Upload data →
              </button>
            )}
          </li>

          <li className="gs-step">
            <span className="gs-num">3</span>
            <div className="gs-body">
              <div className="gs-head">Review findings</div>
              <div className="gs-text">
                Overview, Accounts, Actionable, and Domains light up once data is ingested.
              </div>
            </div>
          </li>
        </ol>
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
