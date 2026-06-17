import { useEffect, useState, type ReactNode } from "react"
import { api, ApiError, type Report, type ReportAccount, type ReuseGroup, type Terms } from "../api"
import { useAudits } from "../auditsData"
import { useAuth } from "../auth"
import { RISK_CLASS, weaknessTags } from "../util"
import { BarChart } from "./BarChart"

const TOP = 50

export function Actionable() {
  const { activeId, dataVersion } = useAudits()
  const { me } = useAuth()
  const [report, setReport] = useState<Report | null>(null)
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(true)
  const [terms, setTerms] = useState<Terms | null>(null)
  const [termsBusy, setTermsBusy] = useState(false)
  const [termsErr, setTermsErr] = useState("")

  async function revealTerms() {
    setTermsBusy(true)
    setTermsErr("")
    try {
      setTerms(await api.reportTerms())
    } catch (e) {
      setTermsErr(e instanceof ApiError ? e.message : "failed to load terms")
    } finally {
      setTermsBusy(false)
    }
  }

  useEffect(() => {
    let live = true
    setLoading(true)
    setTerms(null)
    setTermsErr("")
    api
      .report()
      .then((r) => {
        if (live) {
          setReport(r)
          setError("")
        }
      })
      .catch((e) => {
        if (live) setError(e instanceof ApiError ? e.message : "failed to load report")
      })
      .finally(() => {
        if (live) setLoading(false)
      })
    return () => {
      live = false
    }
  }, [activeId, dataVersion])

  if (error && !report) return <div className="center-state">{error}</div>
  if (loading && !report) {
    return (
      <div className="center-state">
        <div className="spinner">loading</div>
      </div>
    )
  }
  if (!report) return null

  return (
    <>
      <div className="section-label">Actionable reports</div>
      <div className="report-strip">
        <Stat n={report.total_accounts} label="accounts" />
        <Stat n={report.cracked_count} label="cracked" tone="high" />
        <Stat n={report.uncracked_count} label="uncracked" />
        <Stat n={report.cracked_reuse.length} label="cracked-password groups" tone="crit" />
        <Stat n={report.uncracked_reuse.length} label="uncracked-hash groups" tone="med" />
        <Stat n={report.hibp_exposed.length} label="in HIBP" tone="high" />
        <Stat n={report.weak_passwords.length} label="weak (wordlist)" tone="high" />
      </div>

      <Section
        title="Domain Admin Pathways"
        action="Privilege-escalation routes — remediate access / rotate first"
        count={report.da_pathways.length}
        tone="crit"
      >
        <AccountTable
          rows={report.da_pathways}
          metricHead="DA Pathway"
          metric={(a) => <span className="badge crit">{a.da_domains}</span>}
        />
      </Section>

      <Section
        title="Cracked Credentials"
        action="Plaintext recovered by hashcat — force reset; reveal cleartext in Accounts"
        count={report.cracked.length}
        tone="high"
      >
        <AccountTable
          rows={report.cracked}
          metricHead="Length"
          metric={(a) => <span className="c-med">{a.password_length ?? "—"}</span>}
        />
      </Section>

      <Section
        title="Shared Cracked Passwords"
        action="Accounts proven to share the same cracked password — one reset is incomplete; rotate the whole group"
        count={report.cracked_reuse.length}
        tone="crit"
      >
        <ReuseGroups groups={report.cracked_reuse} cracked />
      </Section>

      <Section
        title="Shared Uncracked Passwords"
        action="Same NT hash, password not yet cracked — identical credential reused; lateral-movement risk"
        count={report.uncracked_reuse.length}
        tone="med"
      >
        <ReuseGroups groups={report.uncracked_reuse} />
      </Section>

      <Section
        title="Exposed in Have I Been Pwned"
        action="NT hash found in HIBP (cracked or not) — known-compromised; the count is how many breaches it appears in"
        count={report.hibp_exposed.length}
        tone="high"
      >
        <AccountTable
          rows={report.hibp_exposed}
          metricHead="HIBP breaches"
          metric={(a) => <span className="c-crit">{a.hibp_breach_count.toLocaleString()}</span>}
          sharedCol
        />
      </Section>

      <Section
        title="Weak Passwords"
        action="Cracked password matched a wordlist — common password, dictionary word, forbidden term, or keyboard pattern; force reset"
        count={report.weak_passwords.length}
        tone="high"
      >
        <div className="weak-charts">
          <div className="weak-chart-label">Accounts by violation category</div>
          <BarChart
            rows={[
              { label: "Forbidden", n: report.violation_counts.forbidden },
              { label: "Common", n: report.violation_counts.common },
              { label: "Dictionary", n: report.violation_counts.dictionary },
              { label: "Keyboard", n: report.violation_counts.keyboard },
            ]}
          />
          {me?.role === "lead" && (
            <div className="weak-terms">
              {!terms ? (
                <button className="btn" onClick={() => void revealTerms()} disabled={termsBusy}>
                  {termsBusy ? "Revealing…" : "🔓 Reveal recurring terms"}
                </button>
              ) : (
                <>
                  {terms.forbidden.length === 0 && terms.keyboard.length === 0 ? (
                    <div className="muted">No recurring forbidden words or keyboard patterns.</div>
                  ) : (
                    <>
                      <div className="weak-chart-label">
                        Top recurring terms <span className="muted">— audit-logged reveal; actual words, in-app only</span>
                      </div>
                      {terms.forbidden.length > 0 && (
                        <>
                          <div className="weak-chart-label">Forbidden words</div>
                          <BarChart accent="term" rows={terms.forbidden.slice(0, 10).map((t) => ({ label: t.term, n: t.count }))} />
                        </>
                      )}
                      {terms.keyboard.length > 0 && (
                        <>
                          <div className="weak-chart-label">Keyboard patterns</div>
                          <BarChart accent="term" rows={terms.keyboard.slice(0, 10).map((t) => ({ label: t.term, n: t.count }))} />
                        </>
                      )}
                    </>
                  )}
                </>
              )}
              {termsErr && <div className="error">{termsErr}</div>}
            </div>
          )}
        </div>
        <AccountTable
          rows={report.weak_passwords}
          metricHead="Matched"
          metric={(a) => {
            const t = weaknessTags(a)
            return t.length ? (
              <span className="wtags">
                {t.map((x) => (
                  <span key={x} className="badge wtag">
                    {x}
                  </span>
                ))}
              </span>
            ) : (
              <span className="muted">—</span>
            )
          }}
        />
      </Section>
    </>
  )
}

function Stat({ n, label, tone }: { n: number; label: string; tone?: string }) {
  return (
    <div className="report-stat">
      <span className={`report-stat-n ${tone ? `c-${tone}` : ""}`}>{n.toLocaleString()}</span>
      <span className="report-stat-label">{label}</span>
    </div>
  )
}

function Section({
  title,
  action,
  count,
  tone,
  children,
}: {
  title: string
  action: string
  count: number
  tone: "crit" | "high" | "med"
  children: ReactNode
}) {
  return (
    <div className="action-section">
      <div className="action-head">
        <span className={`action-count ${tone}`}>{count}</span>
        <div>
          <div className="action-title">{title}</div>
          <div className="action-sub">{action}</div>
        </div>
      </div>
      {count === 0 ? <div className="action-empty">none — nothing to action here ✓</div> : children}
    </div>
  )
}

// AccountTable renders a flat list of redacted report rows with one metric column.
function AccountTable({
  rows,
  metricHead,
  metric,
  sharedCol,
}: {
  rows: ReportAccount[]
  metricHead: string
  metric: (a: ReportAccount) => ReactNode
  sharedCol?: boolean
}) {
  const [showAll, setShowAll] = useState(false)
  const shown = showAll ? rows : rows.slice(0, TOP)
  return (
    <div className="table-wrap action-table">
      <table className="accounts">
        <thead>
          <tr>
            <th>Username</th>
            <th>Domain</th>
            <th>Risk</th>
            <th className="num">Score</th>
            {sharedCol && <th className="num">Shared</th>}
            <th>{metricHead}</th>
          </tr>
        </thead>
        <tbody>
          {shown.map((a, i) => (
            <tr key={`${a.domain}/${a.username}/${i}`}>
              <td>
                {a.username}
                {a.enabled === false && <span className="badge-disabled" title="account disabled in AD">disabled</span>}
              </td>
              <td className="muted">{a.domain}</td>
              <td>
                <span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span>
              </td>
              <td className="num">{a.risk_score.toFixed(1)}</td>
              {sharedCol && <td className="num">{a.shared_with > 0 ? a.shared_with : "—"}</td>}
              <td>{metric(a)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > TOP && (
        <div className="meta-line">
          showing {shown.length.toLocaleString()} of {rows.length.toLocaleString()}{" "}
          <button className="link-btn" onClick={() => setShowAll((v) => !v)}>
            {showAll ? "show top 50" : "show all"}
          </button>
        </div>
      )}
    </div>
  )
}

function ReuseGroups({ groups, cracked }: { groups: ReuseGroup[]; cracked?: boolean }) {
  return (
    <div className="reuse-list">
      {groups.slice(0, TOP).map((g) => (
        <ReuseGroupRow key={g.group_id} g={g} cracked={cracked} />
      ))}
      {groups.length > TOP && (
        <div className="meta-line">
          showing top {TOP} of {groups.length.toLocaleString()} groups
        </div>
      )}
    </div>
  )
}

function ReuseGroupRow({ g, cracked }: { g: ReuseGroup; cracked?: boolean }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="reuse-group">
      <button className="reuse-head" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        <span className={`reuse-size badge ${cracked ? "crit" : "med"}`}>{g.size}×</span>
        <span className="reuse-summary">
          accounts share {cracked ? "a cracked password" : "an uncracked password"}
          {cracked && g.password_length ? <span className="muted"> ({g.password_length} chars)</span> : null}
        </span>
        <span className="reuse-meta">
          {g.domains > 1 && (
            <span className="badge med" title="reused across domains">
              {g.domains} domains
            </span>
          )}
          {g.hibp_breach_count > 0 && (
            <span className="badge high" title="appears in HIBP breaches">
              HIBP {g.hibp_breach_count.toLocaleString()}
            </span>
          )}
          {g.has_da_pathway && (
            <span className="badge crit" title="a member can reach Domain Admin">
              DA reachable
            </span>
          )}
        </span>
        <span className="reuse-caret">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div className="table-wrap reuse-members">
          <table className="accounts">
            <thead>
              <tr>
                <th>Username</th>
                <th>Domain</th>
                <th>Risk</th>
                <th className="num">Score</th>
                <th>DA</th>
              </tr>
            </thead>
            <tbody>
              {g.members.map((m, i) => (
                <tr key={`${m.domain}/${m.username}/${i}`}>
                  <td>{m.username}</td>
                  <td className="muted">{m.domain}</td>
                  <td>
                    <span className={`badge ${RISK_CLASS[m.risk_level] || ""}`}>{m.risk_level}</span>
                  </td>
                  <td className="num">{m.risk_score.toFixed(1)}</td>
                  <td>
                    {m.da_domains ? (
                      <span className="badge crit">{m.da_domains}</span>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {g.truncated && (
            <div className="meta-line">
              showing first {g.members.length} of {g.size.toLocaleString()} members
            </div>
          )}
        </div>
      )}
    </div>
  )
}
