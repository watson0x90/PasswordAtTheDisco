import { useEffect, useRef, useState } from "react"
import { api, ApiError, type Account, type Report, type ReportAccount } from "../api"
import { useAccountsData } from "../accountsData"
import { useAudits } from "../auditsData"
import { useAuth } from "../auth"
import { RISK_CLASS } from "../util"
import { crossDomainBridges, hibpTriage, blastRadius, type BridgeCluster } from "../exposure"
import { ExposureHeadline } from "./ExposureHeadline"

export function Exposure() {
  const { me } = useAuth()
  const { accounts, error } = useAccountsData()
  const { activeId, dataVersion } = useAudits()

  const [report, setReport] = useState<Report | null>(null)
  const [reportErr, setReportErr] = useState("")

  const [revealed, setRevealed] = useState<Record<string, string>>({})
  const [revealing, setRevealing] = useState("")
  const [revealError, setRevealError] = useState("")

  const [pairFilter, setPairFilter] = useState<[string, string] | null>(null)
  const [openCluster, setOpenCluster] = useState<string | null>(null)
  const timers = useRef<number[]>([])

  const isLead = me?.role === "lead"

  useEffect(() => {
    let alive = true
    setReport(null)
    setReportErr("")
    api
      .report()
      .then((r) => { if (alive) setReport(r) })
      .catch((e) => { if (alive) setReportErr(e instanceof ApiError ? e.message : "failed to load report") })
    return () => { alive = false }
  }, [activeId, dataVersion])

  useEffect(() => () => { timers.current.forEach(clearTimeout) }, [])

  async function reveal(u: string) {
    setRevealing(u)
    setRevealError("")
    try {
      const r = await api.revealSecret(u)
      setRevealed((p) => ({ ...p, [u]: r.password }))
      timers.current.push(window.setTimeout(() => hide(u), 45000))
    } catch (e) {
      setRevealError(e instanceof ApiError ? `reveal failed: ${e.message}` : "reveal failed")
    } finally {
      setRevealing("")
    }
  }

  function hide(u: string) {
    setRevealed((p) => {
      const n = { ...p }
      delete n[u]
      return n
    })
  }

  if (!activeId) {
    return <div className="center-state">Select or create an audit to view exposure.</div>
  }
  if (accounts === null && !error) {
    return (
      <div className="center-state">
        <div className="spinner">loading</div>
      </div>
    )
  }
  if (error && !accounts) {
    return <div className="center-state">{error}</div>
  }

  const bridges = report ? crossDomainBridges(report) : { matrix: {}, clusters: [] as BridgeCluster[], domains: [] as string[] }
  const triage = report ? hibpTriage(report) : { tier1: [] as ReportAccount[], tier2: [] as ReportAccount[] }
  const work = blastRadius(accounts ?? ([] as Account[]))

  const shown = pairFilter
    ? bridges.clusters.filter(
        (c) => c.domains.includes(pairFilter[0]) && c.domains.includes(pairFilter[1]),
      )
    : bridges.clusters

  return (
    <>
      <ExposureHeadline accounts={accounts ?? []} report={report} />

      {reportErr && (
        <div className="hint">{reportErr} — bridge/HIBP panels need the report.</div>
      )}

      {/* ── Cross-domain credential bridges ── */}
      <div className="section-label">Cross-domain credential bridges</div>
      {bridges.domains.length < 2 ? (
        <div className="panel">
          <div className="muted">No credentials are shared across domains.</div>
        </div>
      ) : (
        <div className="panel">
          <table className="bridge-matrix">
            <thead>
              <tr>
                <th></th>
                {bridges.domains.map((d) => (
                  <th key={d}>{d}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {bridges.domains.map((rowDom) => (
                <tr key={rowDom}>
                  <td className="rowh">{rowDom}</td>
                  {bridges.domains.map((colDom) => {
                    if (colDom <= rowDom) return <td key={colDom} />
                    const n = bridges.matrix[rowDom]?.[colDom] ?? 0
                    return (
                      <td
                        key={colDom}
                        className={`m${n === 0 ? 0 : n < 3 ? 1 : n < 7 ? 2 : 3}`}
                        onClick={n > 0 ? () => setPairFilter([rowDom, colDom]) : undefined}
                      >
                        {n || ""}
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>

          <div className="bridge-clusters">
            {pairFilter && (
              <div className="meta-line">
                showing {pairFilter[0]} ↔ {pairFilter[1]} —{" "}
                <button className="link-btn" onClick={() => setPairFilter(null)}>
                  clear
                </button>
              </div>
            )}
            {shown.map((c, idx) => {
              const cid = c.domains.join("/") + "#" + idx
              return (
                <div key={cid} className="bridge-cluster-row">
                  <span className="muted">{c.domains.join(" ↔ ")}</span>
                  {" · "}
                  {c.size} accounts{" · "}
                  {c.cracked ? "cracked" : "uncracked"}
                  {c.hasDA && <span className="badge crit" style={{ marginLeft: 6 }}>DA</span>}
                  {c.hibpMax > 0 && (
                    <span className="badge" style={{ marginLeft: 6 }}>
                      HIBP {c.hibpMax.toLocaleString()}
                    </span>
                  )}
                  {" "}
                  <button
                    className="link-btn"
                    onClick={() => setOpenCluster(openCluster === cid ? null : cid)}
                  >
                    members ({c.members.length})
                  </button>
                  {openCluster === cid &&
                    c.members.map((m, mi) => (
                      <div key={`${m.domain}/${m.username}/${mi}`} className="member-row">
                        <span className="muted">
                          {m.username} · {m.domain} · {m.risk_level}
                        </span>
                      </div>
                    ))}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* ── HIBP urgency triage ── */}
      <div className="section-label">HIBP urgency triage</div>
      <div className="panel">
        <div className="tier-head">
          <b>Tier 1 · {triage.tier1.length} — cracked + breached</b>
          <div className="muted">exact credential is public → reset now</div>
        </div>
        {triage.tier1.length === 0 ? (
          <div className="muted" style={{ marginBottom: 12 }}>None — no accounts are both cracked and in HIBP.</div>
        ) : (
          <TriageTable rows={triage.tier1} />
        )}

        <div className="tier-head t2">
          <b>Tier 2 · {triage.tier2.length} — breached, not cracked</b>
          <div className="muted">hash in breach data → rotate next cycle</div>
        </div>
        {triage.tier2.length === 0 ? (
          <div className="muted">None — no uncracked accounts appear in HIBP.</div>
        ) : (
          <TriageTable rows={triage.tier2} />
        )}
      </div>

      {/* ── Blast-radius worklist ── */}
      <div className="section-label">Fix these first</div>
      <div className="table-wrap">
        <table className="accounts">
          <thead>
            <tr>
              <th className="num">#</th>
              <th>Account</th>
              <th>Why</th>
              <th>Risk</th>
              {isLead && <th>Secret</th>}
            </tr>
          </thead>
          <tbody>
            {work.map((row, i) => {
              const u = row.account.username
              return (
                <tr key={`${row.account.domain}/${u}/${i}`}>
                  <td className="num">{i + 1}</td>
                  <td>
                    {u}
                    {!row.account.enabled && (
                      <span className="badge-disabled" title="disabled in AD — hash still reusable">
                        disabled
                      </span>
                    )}
                    <span className="muted" style={{ marginLeft: 6 }}>{row.account.domain}</span>
                  </td>
                  <td>
                    {row.reasons.map((r) => (
                      <span key={r} className="badge" style={{ marginRight: 4 }}>
                        {r}
                      </span>
                    ))}
                  </td>
                  <td>
                    <span className={`badge ${RISK_CLASS[row.account.risk_level] || ""}`}>
                      {row.account.risk_level}
                    </span>
                  </td>
                  {isLead && (
                    <td>
                      {!row.account.cracked ? (
                        <span className="muted">uncracked</span>
                      ) : u in revealed ? (
                        <span className="secret">
                          <span className="mono-pw">{revealed[u]}</span>
                          <button className="link-btn" onClick={() => hide(u)}>
                            hide
                          </button>
                        </span>
                      ) : (
                        <button
                          className="reveal-btn"
                          disabled={revealing === u}
                          onClick={() => void reveal(u)}
                        >
                          {revealing === u ? "…" : "reveal"}
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {revealError && <div className="error">{revealError}</div>}
      {isLead && (
        <div className="meta-line">
          ⚠ revealing a credential is recorded in the audit log — operator, account, and timestamp.
        </div>
      )}
    </>
  )
}

function TriageTable({ rows }: { rows: ReportAccount[] }) {
  return (
    <div className="table-wrap" style={{ marginBottom: 16 }}>
      <table className="accounts compact">
        <thead>
          <tr>
            <th>User</th>
            <th>Domain</th>
            <th>Risk</th>
            <th className="num">HIBP#</th>
            <th className="num">Shared</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((a, i) => (
            <tr key={`${a.domain}/${a.username}/${i}`}>
              <td>{a.username}</td>
              <td className="muted">{a.domain}</td>
              <td>
                <span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span>
              </td>
              <td className="num">{a.hibp_breach_count.toLocaleString()}</td>
              <td className="num">{a.shared_with || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
