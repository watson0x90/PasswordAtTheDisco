import { useEffect, useState } from "react"
import { api, ApiError, type Summary } from "../api"
import { useAuth } from "../auth"
import { useAudits } from "../auditsData"
import { useNav } from "../nav"

const RISK_ORDER = ["Critical", "High", "Medium", "Low"]
const RISK_CLASS: Record<string, string> = {
  Critical: "crit",
  High: "high",
  Medium: "med",
  Low: "low",
}

export function Dashboard() {
  const { activeId, audits, loading: auditsLoading } = useAudits()
  const [summary, setSummary] = useState<Summary | null>(null)
  const [error, setError] = useState("")

  useEffect(() => {
    if (!activeId) {
      setSummary(null)
      return
    }
    let active = true
    setSummary(null)
    setError("")
    api
      .summary()
      .then((s) => {
        if (active) setSummary(s)
      })
      .catch((e) => {
        if (active) setError(e instanceof ApiError ? e.message : "failed to load summary")
      })
    return () => {
      active = false
    }
  }, [activeId])

  if (auditsLoading) return <div className="center-state"><div className="spinner">loading</div></div>
  if (!activeId) {
    // auto-select is in flight if audits exist; otherwise there are none
    if (audits.length > 0) return <div className="center-state"><div className="spinner">opening audit</div></div>
    return <NoAudit />
  }
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

// NoAudit is shown when the session has no audit (typically none exist yet).
function NoAudit() {
  const { me } = useAuth()
  const { create } = useAudits()
  const isLead = me?.role === "lead"
  const [name, setName] = useState("")
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState("")

  async function go() {
    if (!name.trim()) return
    setBusy(true)
    setErr("")
    try {
      await create(name.trim())
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "failed to create audit")
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="section-label">Get started</div>
      <div className="panel getstarted">
        <h2 className="gs-title">Create your first audit</h2>
        <p className="gs-sub">
          {isLead
            ? "An audit is a self-contained engagement — its own dataset, scoped views, and findings. Create one to begin (you can run several over time and switch between them up top)."
            : "No audits yet. A lead needs to create one before findings appear."}
        </p>
        {isLead && (
          <div className="audit-create-form gs-create">
            <input
              autoFocus
              className="search"
              placeholder="e.g. Acme Corp — Q2 review"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && go()}
            />
            <button className="btn btn-primary" disabled={busy} onClick={go}>
              Create audit
            </button>
          </div>
        )}
        {err && <div className="error">{err}</div>}
      </div>
    </>
  )
}

function GetStarted() {
  const { me } = useAuth()
  const { active } = useAudits()
  const nav = useNav()
  const isLead = me?.role === "lead"
  return (
    <>
      <div className="section-label">Get started</div>
      <div className="panel getstarted">
        <h2 className="gs-title">Start a password audit</h2>
        <p className="gs-sub">
          {isLead
            ? `No data in ${active ? `“${active.name}”` : "this audit"} yet — follow these steps.`
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
