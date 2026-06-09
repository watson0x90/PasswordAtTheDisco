import { useState, type ReactNode } from "react"
import { useAccountsData } from "../accountsData"
import { RISK_CLASS, hasDA } from "../util"
import type { Account } from "../api"

const TOP = 50

export function Actionable() {
  const { accounts, error } = useAccountsData()

  if (error && !accounts) return <div className="center-state">{error}</div>
  if (!accounts) {
    return (
      <div className="center-state">
        <div className="spinner">loading</div>
      </div>
    )
  }

  const da = accounts.filter((a) => hasDA(a.da_domains)).sort((a, b) => b.risk_score - a.risk_score)
  const breached = accounts.filter((a) => a.hibp_breached).sort((a, b) => b.hibp_breach_count - a.hibp_breach_count)
  const reused = accounts.filter((a) => a.shared_with > 0).sort((a, b) => b.shared_with - a.shared_with)

  return (
    <>
      <div className="section-label">Actionable</div>
      <Section
        title="Domain Admin Pathways"
        action="Privilege-escalation routes — remediate access / rotate first"
        items={da}
        tone="crit"
        metricHead="DA Pathway"
        metric={(a) => <span className="badge crit">{a.da_domains}</span>}
      />
      <Section
        title="Breached Credentials"
        action="Found in Have I Been Pwned — force reset (known-compromised)"
        items={breached}
        tone="high"
        metricHead="HIBP"
        metric={(a) => <span className="c-crit">{a.hibp_breach_count.toLocaleString()}</span>}
      />
      <Section
        title="Reused Passwords"
        action="Shared across accounts — enforce unique credentials"
        items={reused}
        tone="med"
        metricHead="Shared With"
        metric={(a) => <span className="c-med">{a.shared_with}</span>}
      />
    </>
  )
}

interface SectionProps {
  title: string
  action: string
  items: Account[]
  tone: "crit" | "high" | "med"
  metricHead: string
  metric: (a: Account) => ReactNode
}

function Section({ title, action, items, tone, metricHead, metric }: SectionProps) {
  const [showAll, setShowAll] = useState(false)
  const shown = showAll ? items : items.slice(0, TOP)
  return (
    <div className="action-section">
      <div className="action-head">
        <span className={`action-count ${tone}`}>{items.length}</span>
        <div>
          <div className="action-title">{title}</div>
          <div className="action-sub">{action}</div>
        </div>
      </div>
      {items.length === 0 ? (
        <div className="action-empty">none — nothing to action here ✓</div>
      ) : (
        <div className="table-wrap action-table">
          <table className="accounts">
            <thead>
              <tr>
                <th>Username</th>
                <th>Domain</th>
                <th>Risk</th>
                <th className="num">Score</th>
                <th>{metricHead}</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((a, i) => (
                <tr key={`${a.domain}/${a.username}/${i}`}>
                  <td>{a.username}</td>
                  <td className="muted">{a.domain}</td>
                  <td>
                    <span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span>
                  </td>
                  <td className="num">{a.risk_score.toFixed(1)}</td>
                  <td>{metric(a)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {items.length > TOP && (
            <div className="meta-line">
              showing {shown.length.toLocaleString()} of {items.length.toLocaleString()}{" "}
              <button className="link-btn" onClick={() => setShowAll((v) => !v)}>
                {showAll ? "show top 50" : "show all"}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
