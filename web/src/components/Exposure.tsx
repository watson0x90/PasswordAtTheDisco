import { useEffect, useRef, useState } from "react"
import { api, ApiError, type Account, type Report, type ReportAccount } from "../api"
import { useAccountsData } from "../accountsData"
import { useAudits } from "../auditsData"
import { useAuth } from "../auth"
import { RISK_CLASS, hasDA } from "../util"
import { crossDomainBridges, hibpTriage, blastRadius, type BridgeCluster } from "../exposure"
import { topControllers, isReachable } from "../insights"
import { useAccountDrawer } from "../accountDrawer"
import { AccountLink } from "./AccountLink"
import { InfoTip } from "./InfoTip"
import { GLOSSARY } from "../glossary"

export function Exposure() {
  const { me } = useAuth()
  const { accounts, error } = useAccountsData()
  const { activeId, dataVersion } = useAudits()

  const [report, setReport] = useState<Report | null>(null)
  const [reportErr, setReportErr] = useState("")

  const [revealed, setRevealed] = useState<Record<string, string>>({})
  const [revealing, setRevealing] = useState("")
  const [revealError, setRevealError] = useState("")

  const [showAllBridges, setShowAllBridges] = useState(false)
  const [openCluster, setOpenCluster] = useState<string | null>(null)
  const timers = useRef<number[]>([])

  const isLead = me?.role === "lead"
  const { openAccount } = useAccountDrawer()

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
  if (report && report.total_accounts === 0)
    return <div className="center-state">No data yet — select or create an audit and upload a dump.</div>

  const bridges = report ? crossDomainBridges(report) : { clusters: [] as BridgeCluster[], domains: [] as string[] }
  const triage = report ? hibpTriage(report) : { tier1: [] as ReportAccount[], tier2: [] as ReportAccount[] }
  const work = blastRadius(accounts ?? ([] as Account[]))
  // Only the EXPLOITABLE controllers: credential is obtainable (cracked, or the hash is in the
  // HIBP breach corpus even if uncracked). Uncracked-non-HIBP "latent" controllers are excluded.
  const obtainableControllers = (accounts ?? []).filter((a) => a.cracked || a.hibp_breached)
  const { rows: controllerRows, moreOver100 } = topControllers(obtainableControllers, 25)

  const visibleBridges = showAllBridges ? bridges.clusters : bridges.clusters.slice(0, 10)
  const totalBridges = bridges.clusters.length

  return (
    <>
      <div className="section-label">Exposure</div>
      <div className="view-sub">How do attackers move between domains? Cross-domain credential reuse.</div>

      {reportErr && (
        <div className="hint">{reportErr} — bridge/HIBP panels need the report.</div>
      )}

      {/* ── Cross-domain credential bridges ── */}
      <div className="section-label">
        Cross-domain credential bridges<InfoTip text={GLOSSARY.bridge_matrix} />
      </div>
      {bridges.domains.length < 2 ? (
        <div className="panel">
          <div className="muted">No credentials are shared across domains.</div>
        </div>
      ) : (
        <div className="panel">
          <div className="meta-line muted">
            {totalBridges} bridge{totalBridges === 1 ? "" : "s"} — a shared password lets an
            attacker pivot between these domains. Worst first.
          </div>
          <div className="bridge-cards">
            {visibleBridges.map((c) => {
              const cid = c.domains.join("/") + "#" + bridges.clusters.indexOf(c)
              const tier = c.hasDA ? "crit" : c.cracked ? "high" : "low"
              const tierLabel = c.hasDA
                ? "⚠ Reaches Domain Admin"
                : c.cracked
                  ? "Cracked"
                  : "Uncracked — shared hash, no cleartext"
              const open = openCluster === cid
              return (
                <div key={cid} className={`bridge-card ${tier}`}>
                  <div className="bridge-card-head">
                    <div>
                      <div className="bridge-tier">{tierLabel}</div>
                      <div className="bridge-domains">{c.domains.join(" ↔ ")}</div>
                    </div>
                    <div className="bridge-count">
                      <div className="bridge-count-n">{c.size}</div>
                      <div className="bridge-count-l">accounts</div>
                    </div>
                  </div>
                  <div className="bridge-badges">
                    <span className={`badge ${c.cracked ? "high" : ""}`}>{c.cracked ? "cracked" : "uncracked"}</span>
                    {c.hibpMax > 0 && <span className="badge">HIBP {c.hibpMax.toLocaleString()}</span>}
                    <span className="badge">{c.domains.length} domains</span>
                    <button
                      className="link-btn bridge-members-btn"
                      onClick={() => setOpenCluster(open ? null : cid)}
                    >
                      {open ? "▾" : "▸"} {c.members.length} members
                    </button>
                  </div>
                  {open && (
                    <div className="bridge-members">
                      <table className="member-table">
                        <thead>
                          <tr><th>Username</th><th>Domain</th><th>Risk</th><th>Score</th><th>HIBP</th><th>Shared</th></tr>
                        </thead>
                        <tbody>
                          {c.members.map((m, mi) => (
                            <tr key={`${m.domain}/${m.username}/${mi}`}>
                              <td>
                                <AccountLink username={m.username} domain={m.domain} />
                              </td>
                              <td className="muted">{m.domain}</td>
                              <td><span className={`badge ${RISK_CLASS[m.risk_level] || ""}`}>{m.risk_level}</span></td>
                              <td className="num">{m.risk_score.toFixed(1)}</td>
                              <td className="num">{m.hibp_breach_count > 0 ? m.hibp_breach_count.toLocaleString() : "—"}</td>
                              <td className="num">{m.shared_with}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
          {totalBridges > 10 && (
            <button className="link-btn" onClick={() => setShowAllBridges((v) => !v)}>
              {showAllBridges ? "show fewer" : `show all ${totalBridges}`}
            </button>
          )}
        </div>
      )}

      {/* ── HIBP urgency triage ── */}
      <div className="section-label">HIBP urgency triage</div>
      <div className="panel">
        <div className="tier-head">
          <b>Tier 1 · {triage.tier1.length} — cracked + breached</b><InfoTip text={GLOSSARY.tier1_hibp} />
          <div className="muted">exact credential is public → reset now</div>
        </div>
        {triage.tier1.length === 0 ? (
          <div className="muted mb-md">None — no accounts are both cracked and in HIBP.</div>
        ) : (
          <TriageTable rows={triage.tier1} />
        )}

        <div className="tier-head t2">
          <b>Tier 2 · {triage.tier2.length} — breached, not cracked</b><InfoTip text={GLOSSARY.tier2_hibp} />
          <div className="muted">hash in breach data → rotate next cycle</div>
        </div>
        {triage.tier2.length === 0 ? (
          <div className="muted">None — no uncracked accounts appear in HIBP.</div>
        ) : (
          <TriageTable rows={triage.tier2} />
        )}
        <div className="muted triage-note">
          Accounts sharing a password share its breach count (same hash) — repetition is expected, not a duplicate.
        </div>
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
                    <AccountLink username={u} domain={row.account.domain} />
                    {!row.account.enabled && (
                      <span className="badge-disabled" title="disabled in AD — hash still reusable">
                        disabled
                      </span>
                    )}
                    <span className="muted ml-xs">{row.account.domain}</span>
                  </td>
                  <td>
                    <span className="row-gap-xs">
                      {row.reasons.map((r) => (
                        <span key={r} className="badge">
                          {r}
                        </span>
                      ))}
                    </span>
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

      {/* ── Blast-radius: accounts controlling the most objects ── */}
      <div className="section-label">
        Blast radius — cracked / HIBP-exposed accounts controlling the most objects
        <InfoTip text="Accounts whose credential is OBTAINABLE (password cracked, or the NT hash appears in the HIBP breach corpus even if uncracked), ranked by how many AD objects they control. These are the exploitable accounts whose compromise has the widest blast radius. Uncracked accounts not in HIBP are excluded — they're latent, not yet reachable." />
      </div>
      <div className="table-wrap">
        {controllerRows.length === 0 ? (
          <div className="blast-radius-empty muted">
            No cracked or HIBP-exposed accounts control AD objects — run BloodHound enrichment to populate, or none qualify.
          </div>
        ) : (
          <table className="accounts">
            <thead>
              <tr>
                <th className="num">#</th>
                <th>Account</th>
                <th>Domain</th>
                <th className="num">Controlled objects</th>
                <th>Risk</th>
                <th>Flags</th>
              </tr>
            </thead>
            <tbody>
              {controllerRows.map((a, i) => (
                <tr
                  key={`${a.domain}/${a.username}/${i}`}
                  className="blast-radius-row"
                  onClick={() => openAccount(a)}
                >
                  <td className="num blast-radius-rank">{i + 1}</td>
                  <td>
                    <button className="link-btn" onClick={(e) => { e.stopPropagation(); openAccount(a) }}>
                      {a.username}
                    </button>
                    {!a.enabled && (
                      <span className="badge-disabled" title="disabled in AD">disabled</span>
                    )}
                  </td>
                  <td className="muted">{a.domain}</td>
                  <td className="num blast-radius-count">
                    {(a.controlled_object_count || 0).toLocaleString()}
                  </td>
                  <td>
                    <span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>
                      {a.risk_level}
                    </span>
                  </td>
                  <td>
                    <span className="blast-radius-flags">
                      {a.controls_tier0 && (
                        <span className="badge blast-flag-danger" title="Controls Tier-0 objects">T0</span>
                      )}
                      {hasDA(a.da_domains) && (
                        <span className="badge crit" title={`DA pathway: ${a.da_domains}`}>DA</span>
                      )}
                      {a.cracked && (
                        <span className="badge high" title="Password cracked">Crk</span>
                      )}
                      {isReachable(a) && (
                        <span className="badge blast-flag-danger" title="Credential is reachable (enabled + obtainable)">RCH</span>
                      )}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {moreOver100 > 0 && (
        <div className="meta-line">
          +{moreOver100} more account{moreOver100 === 1 ? "" : "s"} control &gt;100 objects.
        </div>
      )}
    </>
  )
}

function TriageTable({ rows }: { rows: ReportAccount[] }) {
  return (
    <div className="table-wrap mb-lg">
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
              <td><AccountLink username={a.username} domain={a.domain} /></td>
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
