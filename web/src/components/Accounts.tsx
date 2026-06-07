import { useEffect, useMemo, useState } from "react"
import { api, ApiError, type Account } from "../api"
import { useAuth } from "../auth"

const RISK_CLASS: Record<string, string> = { Critical: "crit", High: "high", Medium: "med", Low: "low" }
const FILTERS = ["All", "Critical", "High", "Medium", "Low"] as const

export function Accounts() {
  const { me } = useAuth()
  const isLead = me?.role === "lead"

  const [accounts, setAccounts] = useState<Account[] | null>(null)
  const [error, setError] = useState("")
  const [query, setQuery] = useState("")
  const [risk, setRisk] = useState<string>("All")
  const [revealed, setRevealed] = useState<Record<string, string>>({})
  const [revealing, setRevealing] = useState("")

  useEffect(() => {
    api
      .accounts()
      .then(setAccounts)
      .catch((e) => setError(e instanceof ApiError ? e.message : "failed to load accounts"))
  }, [])

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
    setError("")
    try {
      const r = await api.revealSecret(username)
      setRevealed((prev) => ({ ...prev, [username]: r.password }))
    } catch (e) {
      setError(e instanceof ApiError ? `reveal failed: ${e.message}` : "reveal failed")
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

  if (error && !accounts) return <div className="center-state">{error}</div>
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

      {error && <div className="error">{error}</div>}

      <div className="table-wrap">
        <table className="accounts">
          <thead>
            <tr>
              <th>Username</th>
              <th>Domain</th>
              <th>Risk</th>
              <th className="num">Score</th>
              <th className="num">HIBP</th>
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
                <td className="num">{a.shared_with > 0 ? a.shared_with : <span className="muted">0</span>}</td>
                <td>{hasDA(a.da_domains) ? <span className="badge crit">{a.da_domains}</span> : <span className="muted">—</span>}</td>
                {isLead && <td>{revealCell(a, revealed, revealing, reveal, hide)}</td>}
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

function revealCell(
  a: Account,
  revealed: Record<string, string>,
  revealing: string,
  doReveal: (u: string) => void,
  doHide: (u: string) => void,
) {
  if (!a.cracked) return <span className="muted">uncracked</span>
  if (a.username in revealed) {
    return (
      <span className="secret">
        <span className="mono-pw">{revealed[a.username]}</span>
        <button className="link-btn" onClick={() => doHide(a.username)}>
          hide
        </button>
      </span>
    )
  }
  return (
    <button className="reveal-btn" disabled={revealing === a.username} onClick={() => doReveal(a.username)}>
      {revealing === a.username ? "…" : "reveal"}
    </button>
  )
}

function hasDA(da: string): boolean {
  return da !== "" && da !== "None" && da !== "Unknown"
}
