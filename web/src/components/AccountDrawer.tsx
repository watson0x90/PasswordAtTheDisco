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

  // TODO(C5): v2 breakdown reads a.score_breakdown (v2 sub-scores) here.
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
        {/* TODO(C5): v2 breakdown — the v1 Score Breakdown cards read v1 score_breakdown
            fields (base_score, temporal_score, environmental_score, …) that the v2 engine
            no longer emits. C5 rewrites this as Exposure/Impact axis cards (v2 sub-scores,
            provisional handling). Stubbed to {null} in #C1 to keep the tree green. */}
        {null}
      </aside>
    </>
  )
}

// TODO(C5): v2 breakdown — BreakdownCard (Exposure/Impact axis sub-score cards) was
// removed in #C1 along with the v1 Score Breakdown block (noUnusedLocals would flag it
// while unused). C5 restores it to render the v2 Exposure/Impact axis cards.
