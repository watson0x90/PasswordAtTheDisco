import { useEffect, useRef, useState } from "react"
import { api, ApiError, type Account } from "../api"
import { useAuth } from "../auth"
import { RISK_CLASS, hasDA } from "../util"
import { AccountDrawer, WeakCell } from "./AccountDrawer"
import { InfoTip } from "./InfoTip"
import { GLOSSARY } from "../glossary"

// Above this many rows, virtualize (window) the table so we don't mount tens of
// thousands of <tr> nodes. Below it, render all (handles variable-height reveal rows).
const VIRT_THRESHOLD = 200
const ROW_H = 38 // px, must match the CSS row height when virtualizing
const OVERSCAN = 10

export function tableWindow(
  total: number,
  scrollTop: number,
  viewH: number,
): { virtual: boolean; start: number; end: number } {
  const virtual = total > VIRT_THRESHOLD
  if (!virtual) return { virtual: false, start: 0, end: total }
  const start = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN)
  const end = Math.min(total, Math.ceil((scrollTop + viewH) / ROW_H) + OVERSCAN)
  return { virtual, start, end }
}

export function AccountsTable({ accounts }: { accounts: Account[] }) {
  const { me } = useAuth()
  const isLead = me?.role === "lead"

  const [revealed, setRevealed] = useState<Record<string, string>>({})
  const [revealing, setRevealing] = useState("")
  const [revealError, setRevealError] = useState("")
  const [selected, setSelected] = useState<Account | null>(null)

  const scrollRef = useRef<HTMLDivElement>(null)
  const [scrollTop, setScrollTop] = useState(0)
  const [viewH, setViewH] = useState(560)
  const timers = useRef<number[]>([])

  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    setViewH(el.clientHeight)
    const ro = new ResizeObserver(() => setViewH(el.clientHeight)) // keep the window correct on resize
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  useEffect(() => () => { timers.current.forEach(clearTimeout) }, [])

  // reset scroll to top when the accounts set changes (e.g. filter/search in parent)
  useEffect(() => {
    setScrollTop(0)
    if (scrollRef.current) scrollRef.current.scrollTop = 0
  }, [accounts])

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text)
    } catch {
      /* clipboard may be unavailable; ignore */
    }
  }

  async function reveal(username: string) {
    setRevealing(username)
    setRevealError("")
    try {
      const r = await api.revealSecret(username)
      setRevealed((prev) => ({ ...prev, [username]: r.password }))
      timers.current.push(window.setTimeout(() => hide(username), 45000)) // auto-hide after 45s
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

  const total = accounts.length
  const { virtual, start, end } = tableWindow(total, scrollTop, viewH)
  const visible = accounts.slice(start, end)
  const cols = isLead ? 10 : 9

  return (
    <>
      {revealError && <div className="error">{revealError}</div>}

      <div
        className={virtual ? "table-wrap virtual" : "table-wrap"}
        ref={scrollRef}
        onScroll={(e) => virtual && setScrollTop(e.currentTarget.scrollTop)}
      >
        <table className="accounts">
          <thead>
            <tr>
              <th>Username</th>
              <th>Domain</th>
              <th>Risk</th>
              <th className="num">Score<InfoTip text={GLOSSARY.risk_score} /></th>
              <th className="num">HIBP<InfoTip text={GLOSSARY.hibp_count} /></th>
              <th>Policy</th>
              <th>Weak<InfoTip text={GLOSSARY.weak_categories} /></th>
              <th className="num">Shared<InfoTip text={GLOSSARY.shared_with} /></th>
              <th>DA Pathway<InfoTip text={GLOSSARY.da_pathway} /></th>
              {isLead && <th>Secret</th>}
            </tr>
          </thead>
          <tbody>
            {virtual && start > 0 && (
              <tr style={{ height: start * ROW_H }}>
                <td colSpan={cols} />
              </tr>
            )}
            {visible.map((a, i) => (
              <tr key={`${a.domain}/${a.username}/${start + i}`}>
                <td>
                  <button className="link-btn acct-name" onClick={() => setSelected(a)} title="Account details">
                    {a.username}
                  </button>
                  {!a.enabled && <span className="badge-disabled" title="account disabled in AD">disabled</span>}
                </td>
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
                <td><WeakCell a={a} /></td>
                <td className="num">{a.shared_with > 0 ? a.shared_with : <span className="muted">0</span>}</td>
                <td>{hasDA(a.da_domains) ? <span className="badge crit">{a.da_domains}</span> : <span className="muted">—</span>}</td>
                {isLead && (
                  <td>
                    {!a.cracked ? (
                      <span className="muted">uncracked</span>
                    ) : a.username in revealed ? (
                      <span className="secret">
                        <span className="mono-pw">{revealed[a.username]}</span>
                        <button className="link-btn" onClick={() => copy(revealed[a.username])} title="Copy">
                          copy
                        </button>
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
            {virtual && end < total && (
              <tr style={{ height: (total - end) * ROW_H }}>
                <td colSpan={cols} />
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {isLead && (
        <div className="meta-line">⚠ revealing a credential is recorded in the audit log — operator, account, and timestamp.</div>
      )}

      {selected && <AccountDrawer account={selected} onClose={() => setSelected(null)} />}
    </>
  )
}
