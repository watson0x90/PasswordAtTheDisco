import { useEffect, useState } from "react"
import { api, ApiError, type Summary } from "../api"
import { useAuth } from "../auth"
import { useAudits } from "../auditsData"
import { useAccountsData } from "../accountsData"
import { useNav } from "../nav"
import { hasDA } from "../util"
import { riskDistribution, hibpSplit, lengthBuckets } from "../insights"
import { Bars, ChartCard, Donut, PostureGauge } from "./Charts"

const RATING_COLOR: Record<string, string> = { Strong: "#34d399", Fair: "#fbbf24", Weak: "#fb7185", "No Data": "#8a96b2" }
const LIKELIHOOD_COLOR: Record<string, string> = {
  "Very High": "#fb7185",
  High: "#fb7185",
  Medium: "#fbbf24",
  Low: "#34d399",
  "—": "#8a96b2",
}

export function Dashboard() {
  const { activeId, audits, loading: auditsLoading } = useAudits()
  const { accounts, error } = useAccountsData()
  // Posture comes from the server (single source of truth shared with the HTML
  // export + Compare), so the gauge can never drift from the exported report.
  const [summary, setSummary] = useState<Summary | null>(null)
  useEffect(() => {
    if (!activeId) {
      setSummary(null)
      return
    }
    let live = true
    setSummary(null)
    api.summary().then((s) => live && setSummary(s)).catch(() => {})
    return () => {
      live = false
    }
  }, [activeId])

  if (auditsLoading) return <div className="center-state"><div className="spinner">loading</div></div>
  if (!activeId) {
    if (audits.length > 0) return <div className="center-state"><div className="spinner">opening audit</div></div>
    return <NoAudit />
  }
  if (error && !accounts) return <div className="center-state">{error}</div>
  if (!accounts) return <div className="center-state"><div className="spinner">loading</div></div>
  if (accounts.length === 0) return <GetStarted />

  const total = accounts.length
  const cracked = accounts.filter((a) => a.cracked).length
  const breached = accounts.filter((a) => a.hibp_breached).length
  const da = accounts.filter((a) => hasDA(a.da_domains)).length
  const crackPct = total ? Math.round((cracked / total) * 100) : 0

  const p = summary?.posture

  return (
    <>
      <div className="view-head">
        <div className="section-label">Overview</div>
        <div className="export-actions">
          <a className="btn" href="/api/export/csv">Export CSV</a>
          <a className="btn" href="/api/export/html">HTML report</a>
        </div>
      </div>
      <div className="stat-grid">
        <Stat label="Accounts" value={total} delay={0} />
        <Stat label="Cracked" value={cracked} sub={`${crackPct}% of accounts`} delay={0.06} />
        <Stat label="HIBP Breached" value={breached} accent delay={0.12} />
        <Stat label="DA Pathways" value={da} crit delay={0.18} />
      </div>

      <div className="section-label">Security Posture</div>
      <div className="panel posture-panel">
        {p ? (
          <>
            <div className="posture-gauge-wrap">
              <PostureGauge score={p.score} color={RATING_COLOR[p.rating]} rating={p.rating} />
              <div className="posture-likelihood">
                Estimated breach likelihood:{" "}
                <b style={{ color: LIKELIHOOD_COLOR[p.likelihood] }}>{p.likelihood}</b>
              </div>
            </div>
            <div className="posture-breakdown">
              <PostureBar label="Risk distribution" value={p.breakdown.risk} max={40} />
              <PostureBar label="Password strength" value={p.breakdown.strength} max={30} />
              <PostureBar label="Privilege exposure" value={p.breakdown.privilege} max={15} />
              <PostureBar label="Policy compliance" value={p.breakdown.compliance} max={15} />
            </div>
          </>
        ) : (
          <div className="center-state"><div className="spinner">scoring</div></div>
        )}
      </div>

      <div className="section-label">Charts</div>
      <div className="chart-grid">
        <ChartCard title="Risk distribution">
          <Donut data={riskDistribution(accounts)} />
        </ChartCard>
        <ChartCard title="HIBP exposure">
          <Donut data={hibpSplit(accounts)} />
        </ChartCard>
        <ChartCard title="Password length (cracked)">
          <Bars data={lengthBuckets(accounts)} color="#818cf8" />
        </ChartCard>
      </div>
    </>
  )
}

function PostureBar({ label, value, max }: { label: string; value: number; max: number }) {
  return (
    <div className="pbar">
      <div className="pbar-head">
        <span>{label}</span>
        <span className="pbar-val">
          {value} <span className="muted">/ {max}</span>
        </span>
      </div>
      <div className="risk-track">
        <div className="risk-fill bg-low" style={{ width: `${(value / max) * 100}%` }} />
      </div>
    </div>
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
