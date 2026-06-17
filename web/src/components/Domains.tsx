import { useEffect, useState } from "react"
import { api, ApiError, type Account, type Report, type ReportAccount, type ReuseGroup } from "../api"
import { useAccountsData } from "../accountsData"
import { useAudits } from "../auditsData"
import { hasDA } from "../util"
import { hibpSplit, posture, riskDistribution } from "../insights"
import { ChartCard, Donut, PostureGauge } from "./Charts"
import { AccountsTable } from "./AccountsTable"
import { domainDAPaths, domainPolicy, domainQuickWins, domainReuseClusters, domainWordlist } from "../domainData"

const RATING_COLOR: Record<string, string> = { Strong: "#34d399", Fair: "#fbbf24", Weak: "#fb7185", "No Data": "#8a96b2" }

const QUICK_WINS_N = 10

interface DomainStat {
  domain: string
  total: number
  cracked: number
  breached: number
  critical: number
  da: number
}

export function Domains() {
  const { accounts, error } = useAccountsData()
  const [selected, setSelected] = useState<string | null>(null)
  const [report, setReport] = useState<Report | null>(null)
  const [reportErr, setReportErr] = useState("")
  const { activeId, dataVersion } = useAudits()

  useEffect(() => {
    if (selected && accounts && !accounts.some((a) => a.domain === selected)) setSelected(null)
  }, [accounts, selected])

  useEffect(() => {
    let alive = true
    setReport(null); setReportErr("")
    api.report().then((r) => alive && setReport(r)).catch((e) => alive && setReportErr(e instanceof ApiError ? e.message : "report unavailable"))
    return () => { alive = false }
  }, [activeId, dataVersion])

  if (error && !accounts) return <div className="center-state">{error}</div>
  if (!accounts) {
    return (
      <div className="center-state">
        <div className="spinner">loading</div>
      </div>
    )
  }
  if (report && report.total_accounts === 0)
    return <div className="center-state">No data yet — select or create an audit and upload a dump.</div>

  if (selected) {
    const domainAccts = accounts.filter((a) => a.domain === selected)
    if (domainAccts.length) return <DomainDetail domain={selected} accounts={domainAccts} report={report} reportErr={reportErr} onBack={() => setSelected(null)} />
    // else: fall through to the grid (the effect above will clear `selected`)
  }

  const byDomain = new Map<string, DomainStat>()
  for (const a of accounts) {
    let s = byDomain.get(a.domain)
    if (!s) {
      s = { domain: a.domain, total: 0, cracked: 0, breached: 0, critical: 0, da: 0 }
      byDomain.set(a.domain, s)
    }
    s.total++
    if (a.cracked) s.cracked++
    if (a.hibp_breached) s.breached++
    if (a.risk_level === "Critical") s.critical++
    if (hasDA(a.da_domains)) s.da++
  }
  const domains = [...byDomain.values()].sort((a, b) => b.critical - a.critical || b.total - a.total)

  return (
    <>
      <div className="section-label">Domains</div>
      <div className="domain-grid">
        {domains.map((d) => {
          const crackPct = d.total ? Math.round((d.cracked / d.total) * 100) : 0
          return (
            <button className="domain-card domain-card-btn" key={d.domain} onClick={() => setSelected(d.domain)}>
              <div className="domain-card-head">
                <span className="domain-name">{d.domain}</span>
                <span className="domain-pct">{crackPct}% cracked</span>
              </div>
              <div className="domain-stats">
                <DStat label="Accounts" value={d.total} />
                <DStat label="Cracked" value={d.cracked} />
                <DStat label="Breached" value={d.breached} tone="high" />
                <DStat label="Critical" value={d.critical} tone="crit" />
                <DStat label="DA Paths" value={d.da} tone="crit" />
              </div>
              <div className="domain-open">View dashboard →</div>
            </button>
          )
        })}
      </div>
    </>
  )
}

function DomainDetail({ domain, accounts, report, reportErr, onBack }: { domain: string; accounts: Account[]; report: Report | null; reportErr: string; onBack: () => void }) {
  const p = posture(accounts)
  const pol = domainPolicy(accounts)
  const wl = domainWordlist(accounts)
  const quick = domainQuickWins(accounts, QUICK_WINS_N)
  const clusters = report ? domainReuseClusters(report, domain) : { cracked: [], uncracked: [] }
  const daPaths = report ? domainDAPaths(report, domain) : []

  const total = accounts.length
  const cracked = accounts.filter((a) => a.cracked).length
  const breached = accounts.filter((a) => a.hibp_breached).length
  const critical = accounts.filter((a) => a.risk_level === "Critical").length
  const da = accounts.filter((a) => hasDA(a.da_domains)).length

  return (
    <>
      <button className="link-btn domain-back" onClick={onBack}>← All domains</button>
      <div className="section-label">{domain}</div>

      <div className="panel posture-panel">
        <div className="posture-gauge-wrap"><PostureGauge score={p.score} color={RATING_COLOR[p.rating]} rating={p.rating} /></div>
        <div className="domain-detail-stats">
          <DStat label="Accounts" value={total} />
          <DStat label="Cracked" value={cracked} />
          <DStat label="Breached" value={breached} tone="high" />
          <DStat label="Critical" value={critical} tone="crit" />
          <DStat label="DA Paths" value={da} tone="crit" />
        </div>
      </div>

      <div className="domain-strips">
        <div className="panel strip">
          <div className="strip-title">Policy</div>
          <div className="strip-stats"><DStat label="Meets" value={pol.meets} /><DStat label="Fails" value={pol.fails} tone="high" /><DStat label="Disabled" value={pol.disabled} /></div>
        </div>
        <div className="panel strip">
          <div className="strip-title">Wordlist hits</div>
          <div className="strip-stats"><DStat label="Common" value={wl.common} tone="high" /><DStat label="Dictionary" value={wl.dictionary} /><DStat label="Forbidden" value={wl.banned} tone="high" /><DStat label="Keyboard" value={wl.keyboard} /></div>
        </div>
      </div>

      <div className="chart-grid">
        <ChartCard title="Risk distribution"><Donut data={riskDistribution(accounts)} /></ChartCard>
        <ChartCard title="HIBP exposure"><Donut data={hibpSplit(accounts)} /></ChartCard>
      </div>

      {reportErr && <div className="hint">{reportErr} — cluster/DA panels need the report.</div>}

      <ReuseClusters title="Reused passwords (cracked)" groups={clusters.cracked} lateral={false} />
      <ReuseClusters title="Shared uncracked hashes (lateral movement)" groups={clusters.uncracked} lateral={true} />

      <div className="section-label sub">DA-pathway accounts</div>
      <div className="panel">
        {daPaths.length === 0 ? (
          <div className="muted">No BloodHound DA pathways in this domain (run enrichment from Setup → Integrations → BloodHound).</div>
        ) : (
          <table className="accounts compact"><thead><tr><th>Username</th><th>Risk</th><th className="num">HIBP</th><th>DA domains</th></tr></thead>
            <tbody>{daPaths.map((a) => (<tr key={a.username}><td>{a.username}</td><td>{a.risk_level}</td><td className="num">{a.hibp_breach_count || "—"}</td><td className="muted">{a.da_domains ?? "—"}</td></tr>))}</tbody>
          </table>
        )}
      </div>

      <div className="section-label sub">Quick wins — top {QUICK_WINS_N} weakest cracked</div>
      <AccountsTable accounts={quick} />

      <div className="section-label sub">All accounts</div>
      <AccountsTable accounts={accounts} />
    </>
  )
}

function ReuseClusters({ title, groups, lateral }: { title: string; groups: ReuseGroup[]; lateral: boolean }) {
  const [open, setOpen] = useState<number | null>(null)
  return (
    <>
      <div className="section-label sub">{title}</div>
      <div className="panel">
        {groups.length === 0 ? (
          <div className="muted">{lateral ? "No shared uncracked hashes." : "No reused cracked passwords."}</div>
        ) : (
          <table className="accounts compact">
            <thead><tr><th className="num">Accounts</th><th className="num">Domains</th><th>DA?</th><th className="num">HIBP</th>{!lateral && <th className="num">Len</th>}<th></th></tr></thead>
            <tbody>{groups.map((g) => (
              <FragmentRow key={g.group_id} g={g} lateral={lateral} open={open === g.group_id} onToggle={() => setOpen(open === g.group_id ? null : g.group_id)} />
            ))}</tbody>
          </table>
        )}
      </div>
    </>
  )
}

function FragmentRow({ g, lateral, open, onToggle }: { g: ReuseGroup; lateral: boolean; open: boolean; onToggle: () => void }) {
  return (
    <>
      <tr>
        <td className="num">{g.size}</td>
        <td className="num">{g.domains}</td>
        <td>{g.has_da_pathway ? <span className="badge crit">DA</span> : <span className="muted">—</span>}</td>
        <td className="num">{g.hibp_breach_count || "—"}</td>
        {!lateral && <td className="num">{g.password_length ?? "—"}</td>}
        <td><button className="link-btn" onClick={onToggle}>{open ? "hide" : `members (${g.members.length})`}</button></td>
      </tr>
      {open && g.members.map((m: ReportAccount) => (
        <tr key={`${m.domain}/${m.username}`} className="member-row"><td></td><td colSpan={lateral ? 4 : 5} className="muted">{m.username} · {m.domain} · {m.risk_level}</td></tr>
      ))}
    </>
  )
}

function DStat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="dstat">
      <div className={tone ? `dstat-v c-${tone}` : "dstat-v"}>{value.toLocaleString()}</div>
      <div className="dstat-l">{label}</div>
    </div>
  )
}
