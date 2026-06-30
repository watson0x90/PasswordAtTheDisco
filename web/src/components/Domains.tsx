import { useEffect, useMemo, useState } from "react"
import { api, ApiError, type Account, type Report, type ReportAccount, type ReuseGroup, type Summary } from "../api"
import { useAccountsData } from "../accountsData"
import { useAudits } from "../auditsData"
import { hasDA, hasObtainableDA, RISK_CLASS, RISK_RANK } from "../util"
import { OverviewView } from "./Dashboard"
import { domainReport, domainSummary } from "../domainScope"
import { AccountLink } from "./AccountLink"
import { useSortablePaged, type SortColumn } from "../sortPage"
import { SortHeader } from "./SortHeader"
import { Pager } from "./Pager"
import { domainDAPaths, domainReuseClusters } from "../domainData"

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
  const [summary, setSummary] = useState<Summary | null>(null)
  const { activeId, dataVersion } = useAudits()

  useEffect(() => {
    if (selected && accounts && !accounts.some((a) => a.domain === selected)) setSelected(null)
  }, [accounts, selected])

  useEffect(() => {
    let alive = true
    setReport(null); setReportErr(""); setSummary(null)
    api.report().then((r) => alive && setReport(r)).catch((e) => alive && setReportErr(e instanceof ApiError ? e.message : "report unavailable"))
    api.summary().then((s) => alive && setSummary(s)).catch(() => {})
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
    if (domainAccts.length) return <DomainDetail domain={selected} accounts={domainAccts} report={report} reportErr={reportErr} summary={summary} onBack={() => setSelected(null)} />
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
    if (hasObtainableDA(a)) s.da++
  }
  const domains = [...byDomain.values()].sort((a, b) => b.critical - a.critical || b.total - a.total)

  return (
    <>
      <div className="section-label">Domains</div>
      <div className="view-sub">Which domain is worst? Per-domain health.</div>
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

function DomainDetail({ domain, accounts, report, reportErr, summary, onBack }: { domain: string; accounts: Account[]; report: Report | null; reportErr: string; summary: Summary | null; onBack: () => void }) {
  const dSummary = useMemo(() => (summary ? domainSummary(accounts, summary) : null), [accounts, summary])
  const dReport = useMemo(() => domainReport(report, domain, accounts), [report, domain, accounts])

  const clusters = useMemo(
    () => (report ? domainReuseClusters(report, domain) : { cracked: [], uncracked: [] }),
    [report, domain],
  )
  const daPaths = useMemo(() => (report ? domainDAPaths(report, domain) : []), [report, domain])

  const daCols: SortColumn<ReportAccount>[] = [
    { key: "username", get: (a) => a.username },
    { key: "risk", get: (a) => RISK_RANK[a.risk_level] ?? 0, defaultDir: "desc" },
    { key: "score", get: (a) => a.risk_score, defaultDir: "desc" },
    { key: "hibp", get: (a) => a.hibp_breach_count, defaultDir: "desc" },
    { key: "da", get: (a) => a.da_domains ?? "" },
    { key: "controlled", get: (a) => a.controlled_object_count, defaultDir: "desc" },
  ]
  const detailCols: SortColumn<Account>[] = [
    { key: "username", get: (a) => a.username },
    { key: "risk", get: (a) => RISK_RANK[a.risk_level] ?? 0, defaultDir: "desc" },
    { key: "score", get: (a) => a.risk_score, defaultDir: "desc" },
    { key: "hibp", get: (a) => a.hibp_breach_count, defaultDir: "desc" },
    { key: "shared", get: (a) => a.shared_with, defaultDir: "desc" },
    { key: "days", get: (a) => a.days_out_of_compliance ?? 0, defaultDir: "desc" },
    { key: "controlled", get: (a) => a.controlled_object_count ?? 0, defaultDir: "desc" },
    { key: "enabled", get: (a) => !!a.enabled },
    { key: "da", get: (a) => a.da_domains ?? "" },
  ]
  const escalatedRows = useMemo(() => accounts.filter((a) => a.escalated_by_shared_da), [accounts])
  const staleRows = useMemo(() => accounts.filter((a) => (a.days_out_of_compliance ?? 0) > 0), [accounts])
  const neverExpiresRows = useMemo(() => accounts.filter((a) => a.pwd_never_expires === true), [accounts])
  const kerberoastRows = useMemo(() => accounts.filter((a) => a.has_spn === true), [accounts])

  const daPage = useSortablePaged(daPaths, daCols, { defaultSort: { key: "score", dir: "desc" } })
  const escalatedPage = useSortablePaged(escalatedRows, detailCols, { defaultSort: { key: "score", dir: "desc" } })
  const stalePage = useSortablePaged(staleRows, detailCols, { defaultSort: { key: "days", dir: "desc" } })
  const neverExpiresPage = useSortablePaged(neverExpiresRows, detailCols, { defaultSort: { key: "score", dir: "desc" } })
  const kerberoastPage = useSortablePaged(kerberoastRows, detailCols, { defaultSort: { key: "score", dir: "desc" } })

  return (
    <>
      <button className="link-btn domain-back" onClick={onBack}>← All domains</button>

      <OverviewView accounts={accounts} summary={dSummary} report={dReport} title={domain} subtitle="Where does this domain stand?" />

      <div className="section-label">Domain drill-down</div>
      {reportErr && <div className="hint">{reportErr} — cluster/DA panels need the report.</div>}

      <div className="section-label sub">DA-pathway accounts</div>
      <div className="panel">
        {daPaths.length === 0 ? (
          <div className="muted">No BloodHound DA pathways in this domain.</div>
        ) : (
          <>
            <table className="accounts compact"><thead><tr>
              <SortHeader label="Username" colKey="username" sort={daPage.sort} onSort={daPage.setSort} />
              <SortHeader label="Risk" colKey="risk" sort={daPage.sort} onSort={daPage.setSort} />
              <SortHeader label="Score" colKey="score" numeric sort={daPage.sort} onSort={daPage.setSort} />
              <SortHeader label="HIBP" colKey="hibp" numeric sort={daPage.sort} onSort={daPage.setSort} />
              <SortHeader label="DA domains" colKey="da" sort={daPage.sort} onSort={daPage.setSort} />
              <SortHeader label="Controlled" colKey="controlled" numeric sort={daPage.sort} onSort={daPage.setSort} />
            </tr></thead>
              <tbody>{daPage.rows.map((a) => (<tr key={a.username}><td><AccountLink username={a.username} domain={a.domain} /></td><td><span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span></td><td className="num">{a.risk_score.toFixed(1)}</td><td className="num">{a.hibp_breach_count || "—"}</td><td className="muted">{a.da_domains ?? "—"}</td><td className="num">{a.controlled_object_count || "—"}</td></tr>))}</tbody>
            </table>
            <Pager page={daPage} />
          </>
        )}
      </div>

      <ReuseClusters title="Reused passwords (cracked)" groups={clusters.cracked} lateral={false} />
      <ReuseClusters title="Shared uncracked hashes (lateral movement)" groups={clusters.uncracked} lateral={true} />

      <div className="section-label sub">Escalated by Shared-DA</div>
      <div className="panel">
        {escalatedRows.length === 0 ? (
          <div className="muted">No accounts escalated via hash-sharing with a DA.</div>
        ) : (
          <>
            <table className="accounts compact"><thead><tr>
              <SortHeader label="Username" colKey="username" sort={escalatedPage.sort} onSort={escalatedPage.setSort} />
              <SortHeader label="Risk" colKey="risk" sort={escalatedPage.sort} onSort={escalatedPage.setSort} />
              <SortHeader label="Score" colKey="score" numeric sort={escalatedPage.sort} onSort={escalatedPage.setSort} />
              <SortHeader label="Shared" colKey="shared" numeric sort={escalatedPage.sort} onSort={escalatedPage.setSort} />
            </tr></thead>
              <tbody>{escalatedPage.rows.map((a) => (
                <tr key={a.username}><td><AccountLink username={a.username} domain={a.domain} /></td><td><span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span></td><td className="num">{a.risk_score.toFixed(1)}</td><td className="num">{a.shared_with}</td></tr>
              ))}</tbody>
            </table>
            <Pager page={escalatedPage} />
          </>
        )}
      </div>

      <div className="section-label sub">Stale passwords (past max age)</div>
      <div className="panel">
        {staleRows.length === 0 ? (
          <div className="muted">No stale passwords in this domain.</div>
        ) : (
          <>
            <table className="accounts compact"><thead><tr>
              <SortHeader label="Username" colKey="username" sort={stalePage.sort} onSort={stalePage.setSort} />
              <SortHeader label="Risk" colKey="risk" sort={stalePage.sort} onSort={stalePage.setSort} />
              <SortHeader label="Score" colKey="score" numeric sort={stalePage.sort} onSort={stalePage.setSort} />
              <SortHeader label="Days overdue" colKey="days" numeric sort={stalePage.sort} onSort={stalePage.setSort} />
              <SortHeader label="Enabled" colKey="enabled" sort={stalePage.sort} onSort={stalePage.setSort} />
            </tr></thead>
              <tbody>{stalePage.rows.map((a) => (
                <tr key={a.username}><td><AccountLink username={a.username} domain={a.domain} /></td><td><span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span></td><td className="num">{a.risk_score.toFixed(1)}</td><td className="num">{a.days_out_of_compliance}d</td><td>{a.enabled ? "Yes" : <span className="muted">No</span>}</td></tr>
              ))}</tbody>
            </table>
            <Pager page={stalePage} />
          </>
        )}
      </div>

      <div className="section-label sub">Password never expires</div>
      <div className="panel">
        {neverExpiresRows.length === 0 ? (
          <div className="muted">No accounts with non-expiring passwords.</div>
        ) : (
          <>
            <table className="accounts compact"><thead><tr>
              <SortHeader label="Username" colKey="username" sort={neverExpiresPage.sort} onSort={neverExpiresPage.setSort} />
              <SortHeader label="Risk" colKey="risk" sort={neverExpiresPage.sort} onSort={neverExpiresPage.setSort} />
              <SortHeader label="Score" colKey="score" numeric sort={neverExpiresPage.sort} onSort={neverExpiresPage.setSort} />
              <SortHeader label="HIBP" colKey="hibp" numeric sort={neverExpiresPage.sort} onSort={neverExpiresPage.setSort} />
              <SortHeader label="Enabled" colKey="enabled" sort={neverExpiresPage.sort} onSort={neverExpiresPage.setSort} />
            </tr></thead>
              <tbody>{neverExpiresPage.rows.map((a) => (
                <tr key={a.username}><td><AccountLink username={a.username} domain={a.domain} /></td><td><span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span></td><td className="num">{a.risk_score.toFixed(1)}</td><td className="num">{a.hibp_breached ? a.hibp_breach_count.toLocaleString() : "—"}</td><td>{a.enabled ? "Yes" : <span className="muted">No</span>}</td></tr>
              ))}</tbody>
            </table>
            <Pager page={neverExpiresPage} />
          </>
        )}
      </div>

      <div className="section-label sub">Kerberoastable accounts</div>
      <div className="panel">
        {kerberoastRows.length === 0 ? (
          <div className="muted">No Kerberoastable accounts in this domain.</div>
        ) : (
          <>
            <table className="accounts compact"><thead><tr>
              <SortHeader label="Username" colKey="username" sort={kerberoastPage.sort} onSort={kerberoastPage.setSort} />
              <SortHeader label="Risk" colKey="risk" sort={kerberoastPage.sort} onSort={kerberoastPage.setSort} />
              <SortHeader label="Score" colKey="score" numeric sort={kerberoastPage.sort} onSort={kerberoastPage.setSort} />
              <SortHeader label="DA" colKey="da" sort={kerberoastPage.sort} onSort={kerberoastPage.setSort} />
              <SortHeader label="Controlled" colKey="controlled" numeric sort={kerberoastPage.sort} onSort={kerberoastPage.setSort} />
            </tr></thead>
              <tbody>{kerberoastPage.rows.map((a) => (
                <tr key={a.username}><td><AccountLink username={a.username} domain={a.domain} /></td><td><span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span></td><td className="num">{a.risk_score.toFixed(1)}</td><td>{hasDA(a.da_domains) ? <span className="badge crit">{a.da_domains}</span> : "—"}</td><td className="num">{a.controlled_object_count || "—"}</td></tr>
              ))}</tbody>
            </table>
            <Pager page={kerberoastPage} />
          </>
        )}
      </div>
    </>
  )
}

function ReuseClusters({ title, groups, lateral }: { title: string; groups: ReuseGroup[]; lateral: boolean }) {
  const [open, setOpen] = useState<number | null>(null)
  const reuseCols: SortColumn<ReuseGroup>[] = [
    { key: "accounts", get: (g) => g.size, defaultDir: "desc" },
    { key: "domains", get: (g) => g.domains, defaultDir: "desc" },
    { key: "hibp", get: (g) => g.hibp_breach_count, defaultDir: "desc" },
    { key: "len", get: (g) => g.password_length ?? 0, defaultDir: "desc" },
  ]
  const page = useSortablePaged(groups, reuseCols, { defaultSort: { key: "accounts", dir: "desc" } })
  return (
    <>
      <div className="section-label sub">{title}</div>
      <div className="panel">
        {groups.length === 0 ? (
          <div className="muted">{lateral ? "No shared uncracked hashes." : "No reused cracked passwords."}</div>
        ) : (
          <>
            <table className="accounts compact">
              <thead><tr>
                <SortHeader label="Accounts" colKey="accounts" numeric sort={page.sort} onSort={page.setSort} />
                <SortHeader label="Domains" colKey="domains" numeric sort={page.sort} onSort={page.setSort} />
                <th>DA?</th>
                <SortHeader label="HIBP" colKey="hibp" numeric sort={page.sort} onSort={page.setSort} />
                {!lateral && <SortHeader label="Len" colKey="len" numeric sort={page.sort} onSort={page.setSort} />}
                <th></th>
              </tr></thead>
              <tbody>{page.rows.map((g) => (
                <FragmentRow key={g.group_id} g={g} lateral={lateral} open={open === g.group_id} onToggle={() => setOpen(open === g.group_id ? null : g.group_id)} />
              ))}</tbody>
            </table>
            <Pager page={page} />
          </>
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
        <tr key={`${m.domain}/${m.username}`} className="member-row"><td></td><td colSpan={lateral ? 4 : 5} className="muted"><AccountLink username={m.username} domain={m.domain} /> · {m.domain} · {m.risk_level}</td></tr>
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
