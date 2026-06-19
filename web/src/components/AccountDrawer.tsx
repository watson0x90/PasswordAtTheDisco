import { useEffect, type ReactNode } from "react"
import type { Account } from "../api"
import { RISK_CLASS, hasDA, weaknessTags } from "../util"

// WeakCell shows wordlist-weakness badges (common / dictionary / forbidden /
// keyboard). The matched word itself is never shown — only the category.
export function WeakCell({ a }: { a: Account }) {
  const tags = weaknessTags(a)
  if (!tags.length) return <span className="muted">—</span>
  return (
    <span className="wtags" title="password matched a wordlist">
      {tags.map((t) => (
        <span key={t} className="badge wtag">
          {t}
        </span>
      ))}
    </span>
  )
}

export function AccountDrawer({ account: a, onClose }: { account: Account; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose()
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [onClose])

  function fmtAge(epoch: number | undefined): string {
    if (!epoch || epoch <= 0) return "Unknown"
    const days = Math.floor((Date.now() / 1000 - epoch) / 86400)
    if (days < 1) return "Today"
    if (days < 30) return `${days}d ago`
    if (days < 365) return `${Math.floor(days / 30)}mo ago`
    return `${(days / 365).toFixed(1)}y ago`
  }

  const rows: [string, ReactNode][] = [
    ["Domain", a.domain],
    ["Status", a.cracked ? "Cracked" : "Uncracked"],
    ["Risk level", <span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span>],
    ["Risk score", a.risk_score.toFixed(1)],
    ["Risk vector", <code className="vector">{a.risk_vector || "—"}</code>],
    ["HIBP breaches", a.hibp_breached ? a.hibp_breach_count.toLocaleString() : "—"],
    ["Complexity", a.cracked ? a.complexity : "—"],
    ["Password length", a.cracked ? a.password_length : "—"],
    ["Meets policy", a.cracked ? (a.meets_policy ? "Yes" : "No") : "—"],
    [
      "Weaknesses",
      !a.cracked ? "—" : weaknessTags(a).length ? <WeakCell a={a} /> : <span className="muted">none</span>,
    ],
    ["Similarity", a.cracked && (a.similarity_score ?? 0) > 0 ? `${((a.similarity_score ?? 0) * 100).toFixed(0)}% match to another password` : "—"],
    ["Shared with", a.shared_with],
    ["DA pathway", hasDA(a.da_domains) ? a.da_domains : "—"],
    ["Controlled objects", a.controlled_object_count],
    ["Password last set", fmtAge(a.pwd_last_set)],
    ["Password never expires", a.pwd_never_expires === true ? "Yes ⚠" : a.pwd_never_expires === false ? "No" : "Unknown"],
    ["Days out of compliance", a.days_out_of_compliance ? `${a.days_out_of_compliance}d overdue` : "—"],
    ["Escalated (Shared-DA)", a.escalated_by_shared_da ? "Yes — shares hash with a DA account" : "—"],
    ["Kerberoastable (SPN)", a.has_spn === true ? "Yes ⚠ — offline crackable via TGS" : "No"],
    ["AS-REP roastable", a.dont_req_preauth === true ? "Yes ⚠ — no pre-auth required" : "No"],
    ["Enabled", a.enabled ? "Yes" : "No"],
  ]

  const bd = a.score_breakdown
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Account ${a.username}`}>
        <div className="drawer-head">
          <span className="drawer-title">{a.username}</span>
          <button className="link-btn" onClick={onClose}>
            close
          </button>
        </div>
        <dl className="drawer-fields">
          {rows.map(([k, v]) => (
            <div className="drawer-row" key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
        {bd && (
          <div className="drawer-breakdown">
            <div className="drawer-section-title">Score Breakdown</div>
            <div className="breakdown-grid">
              <BreakdownCard title="Base" score={bd.base_score} factors={[
                ["Complexity", bd.complexity_factor],
                ["Length", bd.length_factor],
                ["Dictionary", bd.dictionary_factor],
                ["Similarity", bd.similarity_factor],
              ]} />
              <BreakdownCard title="Temporal" score={bd.temporal_score} factors={[
                ["Compliance", bd.compliance_factor],
                ["Expiration", bd.expiration_factor],
              ]} />
              <BreakdownCard title="Environmental" score={bd.environmental_score} factors={[
                ["Privilege", bd.privilege_factor],
                ["Sharing", bd.share_factor],
                ["Domain", bd.domain_factor],
                ["HIBP", bd.hibp_factor],
              ]} />
            </div>
          </div>
        )}
      </aside>
    </>
  )
}

function BreakdownCard({ title, score, factors }: { title: string; score: number; factors: [string, number][] }) {
  return (
    <div className="bd-card">
      <div className="bd-card-head">
        <span className="bd-card-title">{title}</span>
        <span className="bd-card-score">{score.toFixed(1)}</span>
      </div>
      <div className="bd-card-factors">
        {factors.map(([label, val]) => (
          <div className="bd-factor" key={label}>
            <span>{label}</span>
            <span className="mono">{val.toFixed(2)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
