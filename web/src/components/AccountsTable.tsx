import { useEffect, useRef, useState } from "react"
import { api, ApiError, type Account } from "../api"
import { useAuth } from "../auth"
import { RISK_CLASS, RISK_RANK, hasDA, weaknessTags } from "../util"
import { useSortablePaged, type SortColumn } from "../sortPage"
import { SortHeader } from "./SortHeader"
import { Pager } from "./Pager"
import { WeakCell } from "./AccountDrawer"
import { AccountLink } from "./AccountLink"
import { InfoTip } from "./InfoTip"
import { GLOSSARY } from "../glossary"
import { impactIsKnown, isProvisional, coverageState } from "../accountFlags"

export function AccountsTable({ accounts }: { accounts: Account[] }) {
  const { me } = useAuth()
  const isLead = me?.role === "lead"

  const [revealed, setRevealed] = useState<Record<string, string>>({})
  const [revealing, setRevealing] = useState("")
  const [revealError, setRevealError] = useState("")
  const timers = useRef<number[]>([])

  useEffect(() => () => { timers.current.forEach(clearTimeout) }, [])

  const COLS: SortColumn<Account>[] = [
    { key: "username", get: (a) => a.username },
    { key: "domain", get: (a) => a.domain },
    { key: "risk", get: (a) => RISK_RANK[a.risk_level] ?? 0, defaultDir: "desc" },
    { key: "exposure", get: (a) => a.exposure_score, defaultDir: "desc" },
    // Impact sorts known-desc; Unknown rows return null so sortRows groups them LAST in
    // BOTH directions (never interleaved as if low-impact), matching the sibling policy
    // column's null-last idiom. impact_score is never coalesced to 0.
    { key: "impact", get: (a) => (impactIsKnown(a) ? (a.impact_score as number) : null), defaultDir: "desc" },
    { key: "score", get: (a) => a.risk_score, defaultDir: "desc" },
    { key: "hibp", get: (a) => a.hibp_breach_count, defaultDir: "desc" },
    { key: "policy", get: (a) => (!a.cracked ? null : a.meets_policy ? 1 : 0) },
    { key: "weak", get: (a) => weaknessTags(a).length, defaultDir: "desc" },
    { key: "shared", get: (a) => a.shared_with, defaultDir: "desc" },
    { key: "da", get: (a) => a.da_domains ?? "" },
  ]
  const page = useSortablePaged(accounts, COLS, { defaultSort: { key: "score", dir: "desc" } })

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text)
    } catch {
      /* clipboard may be unavailable; ignore */
    }
  }

  async function reveal(username: string, domain: string) {
    const key = `${domain}/${username}`
    setRevealing(key)
    setRevealError("")
    try {
      const r = await api.revealSecret(username, domain)
      setRevealed((prev) => ({ ...prev, [key]: r.password }))
      timers.current.push(window.setTimeout(() => hide(key), 45000)) // auto-hide after 45s
    } catch (e) {
      setRevealError(e instanceof ApiError ? `reveal failed: ${e.message}` : "reveal failed")
    } finally {
      setRevealing("")
    }
  }

  function hide(key: string) {
    setRevealed((prev) => {
      const next = { ...prev }
      delete next[key]
      return next
    })
  }

  return (
    <>
      {revealError && <div className="error">{revealError}</div>}

      <div className="table-wrap">
        <table className="accounts">
          <thead>
            <tr>
              <SortHeader label="Username" colKey="username" sort={page.sort} onSort={page.setSort} />
              <SortHeader label="Domain" colKey="domain" sort={page.sort} onSort={page.setSort} />
              <SortHeader label="Risk" colKey="risk" sort={page.sort} onSort={page.setSort} />
              <SortHeader label="Exposure" colKey="exposure" numeric sort={page.sort} onSort={page.setSort} info={<InfoTip text={GLOSSARY.exposure_axis} />} />
              <SortHeader label="Impact" colKey="impact" numeric sort={page.sort} onSort={page.setSort} info={<InfoTip text={GLOSSARY.impact_axis} />} />
              <SortHeader label="Score" colKey="score" numeric sort={page.sort} onSort={page.setSort} info={<InfoTip text={GLOSSARY.risk_score} />} />
              <SortHeader label="HIBP" colKey="hibp" numeric sort={page.sort} onSort={page.setSort} info={<InfoTip text={GLOSSARY.hibp_count} />} />
              <SortHeader label="Policy" colKey="policy" sort={page.sort} onSort={page.setSort} />
              <SortHeader label="Weak" colKey="weak" sort={page.sort} onSort={page.setSort} info={<InfoTip text={GLOSSARY.weak_categories} />} />
              <SortHeader label="Shared" colKey="shared" numeric sort={page.sort} onSort={page.setSort} info={<InfoTip text={GLOSSARY.shared_with} />} />
              <SortHeader label="DA Pathway" colKey="da" sort={page.sort} onSort={page.setSort} info={<InfoTip text={GLOSSARY.da_pathway} />} />
              {isLead && <th>Secret</th>}
            </tr>
          </thead>
          <tbody>
            {page.rows.map((a) => (
              <tr key={`${a.domain}/${a.username}`}>
                <td>
                  <AccountLink username={a.username} domain={a.domain} />
                  {!a.enabled && <span className="badge-disabled" title="account disabled in AD">disabled</span>}
                </td>
                <td className="muted">
                  {a.domain}
                  {coverageState(a) === "none" && (
                    <span className="badge-no-bh" title="not BloodHound-enriched — Impact is Unknown">no BH</span>
                  )}
                </td>
                <td>
                  <span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span>
                  {isProvisional(a) && (
                    <span className="badge-provisional" title={GLOSSARY.impact_unknown}>provisional</span>
                  )}
                </td>
                <td className="num">{a.exposure_score.toFixed(1)}</td>
                <td className="num">
                  {impactIsKnown(a) ? (
                    (a.impact_score as number).toFixed(1)
                  ) : (
                    <span className="badge-provisional" title={GLOSSARY.impact_unknown}>Unknown</span>
                  )}
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
                    {(() => {
                      const key = `${a.domain}/${a.username}`
                      if (!a.cracked) return <span className="muted">uncracked</span>
                      if (key in revealed) {
                        return (
                          <span className="secret">
                            <span className="mono-pw">{revealed[key]}</span>
                            <button className="link-btn" onClick={() => copy(revealed[key])} title="Copy">copy</button>
                            <button className="link-btn" onClick={() => hide(key)}>hide</button>
                          </span>
                        )
                      }
                      return (
                        <button className="reveal-btn" disabled={revealing === key} onClick={() => reveal(a.username, a.domain)}>
                          {revealing === key ? "…" : "reveal"}
                        </button>
                      )
                    })()}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Pager page={page} />

      {isLead && (
        <div className="meta-line">⚠ revealing a credential is recorded in the audit log — operator, account, and timestamp.</div>
      )}
    </>
  )
}
