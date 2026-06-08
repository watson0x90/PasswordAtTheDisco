import { useMemo, useState } from "react"
import { api, ApiError } from "../api"
import { useAccountsData } from "../accountsData"
import { useAuth } from "../auth"
import { RISK_CLASS, hasDA } from "../util"

const FILTERS = ["All", "Critical", "High", "Medium", "Low"] as const

export function Accounts() {
  const { me } = useAuth()
  const { accounts, error: loadError } = useAccountsData()
  const isLead = me?.role === "lead"

  const [query, setQuery] = useState("")
  const [risk, setRisk] = useState<string>("All")
  const [revealed, setRevealed] = useState<Record<string, string>>({})
  const [revealing, setRevealing] = useState("")
  const [revealError, setRevealError] = useState("")

  const filtered = useMemo(() => {
    if (!accounts) return []
    const needle = query.trim().toLowerCase()
    return accounts.filter((a) => {
      if (risk !== "All" && a.risk_level !== risk) return false
      if (needle && !`${a.username} ${a.domain}`.toLowerCase().includes(needle)) return false
      return true
    })
  }, [accounts, query, risk])

  async function reveal(username: string) {
    setRevealing(username)
    setRevealError("")
    try {
      const r = await api.revealSecret(username)
      setRevealed((prev) => ({ ...prev, [username]: r.password }))
    } catch (e) {
      setRevealError(e instanceof ApiError ? `reveal failed: ${e.message}` : "reveal failed")
    } finally {
      setRevealing("")
    }
  }

  function hide(username: string) {
    setRevealed((prev) => {
      const next = { ...prev }
      delete next[username]
      return next
    })
  }

  if (loadError && !accounts) return <div className="center-state">{loadError}</div>
  if (!accounts) {
    return (
      <div className="center-state">
        <div className="spinner">loading</div>
      </div>
    )
  }

  return (
    <>
      <div className="section-label">Accounts</div>

      <div className="toolbar">
        <input
          className="search"
          placeholder="search username or domain…"
          value={query}
          spellCheck={false}
          onChange={(e) => setQuery(e.target.value)}
        />
        <div className="filter-pills">
          {FILTERS.map((f) => {
            const active = f === risk
            const cls = active ? `pill active ${f !== "All" ? RISK_CLASS[f] : ""}` : "pill"
            return (
              <button key={f} className={cls} onClick={() => setRisk(f)}>
                {f}
              </button>
            )
          })}
        </div>
        <div className="toolbar-count">
          {filtered.length.toLocaleString()} / {accounts.length.toLocaleString()}
        </div>
      </div>

      {revealError && <div className="error">{revealError}</div>}

      <div className="table-wrap">
        <table className="accounts">
          <thead>
            <tr>
              <th>Username</th>
              <th>Domain</th>
              <th>Risk</th>
              <th className="num">Score</th>
              <th className="num">HIBP</th>
              <th>Policy</th>
              <th className="num">Shared</th>
              <th>DA Pathway</th>
              {isLead && <th>Secret</th>}
            </tr>
          </thead>
          <tbody>
            {filtered.map((a, i) => (
              <tr key={`${a.domain}/${a.username}/${i}`}>
                <td>{a.username}</td>
                <td className="muted">{a.domain}</td>
                <td>
                  <span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span>
                </td>
                <td className="num">{a.risk_score.toFixed(1)}</td>
                <td className="num">
                  {a.hibp_breached ? <span className="c-crit">{a.hibp_breach_count.toLocaleString()}</span> : <span className="muted">—</span>}
                </td>
                <td>
                  {!a.cracked ? (
                    <span className="muted">—</span>
                  ) : a.meets_policy ? (
                    <span className="c-low">✓ meets</span>
                  ) : (
                    <span className="c-high">✗ fails</span>
                  )}
                </td>
                <td className="num">{a.shared_with > 0 ? a.shared_with : <span className="muted">0</span>}</td>
                <td>{hasDA(a.da_domains) ? <span className="badge crit">{a.da_domains}</span> : <span className="muted">—</span>}</td>
                {isLead && (
                  <td>
                    {!a.cracked ? (
                      <span className="muted">uncracked</span>
                    ) : a.username in revealed ? (
                      <span className="secret">
                        <span className="mono-pw">{revealed[a.username]}</span>
                        <button className="link-btn" onClick={() => hide(a.username)}>
                          hide
                        </button>
                      </span>
                    ) : (
                      <button className="reveal-btn" disabled={revealing === a.username} onClick={() => reveal(a.username)}>
                        {revealing === a.username ? "…" : "reveal"}
                      </button>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {isLead && (
        <div className="meta-line">⚠ revealing a credential is recorded in the audit log — operator, account, and timestamp.</div>
      )}
    </>
  )
}
