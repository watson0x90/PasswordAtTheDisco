import { useEffect } from "react"
import type { Account } from "../api"
import { accountFactRows, RiskTiles, WhyCallout, pickFacts, WeakCell } from "./accountFacts"
import { RISK_CLASS } from "../util"
import { useAccountDetail } from "../accountDetail"

export { WeakCell }

// Curated high-signal facts for the quick peek; the full detail page shows everything.
// pickFacts drops empty "—" rows, so flag-style facts (DA pathway, escalations) only
// appear when actually set.
const PEEK_FACTS = [
  "Password length", "Meets policy", "Weaknesses", "Shared with",
  "DA pathway", "Controls Tier-0", "Escalated (Shared-DA)", "Escalated (Mass-reuse)",
]

// AccountDrawer is the quick-peek slide-out: identity, the shared risk tiles + why
// callout, a few high-signal facts, and a prominent CTA to the full detail page.
export function AccountDrawer({ account: a, onClose }: { account: Account; onClose: () => void }) {
  const { open: openDetail } = useAccountDetail()

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose()
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [onClose])

  const facts = pickFacts(accountFactRows(a), PEEK_FACTS)

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Account ${a.username}`}>
        <div className="drawer-head">
          <span className="drawer-title">{a.username}</span>
          <button className="link-btn" onClick={onClose}>close</button>
        </div>
        <div className="drawer-badge-row">
          <span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span>
          <span className="muted">
            {a.domain} · {a.cracked ? "Cracked" : "Uncracked"} · {a.enabled ? "Enabled" : "Disabled"}
          </span>
        </div>

        <WhyCallout a={a} />
        <RiskTiles a={a} />

        {facts.length > 0 && (
          <dl className="ad-facts drawer-peek-facts">
            {facts.map(([k, v]) => (
              <div className="ad-fact" key={k}>
                <dt>{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
        )}

        <button
          className="ad-cta"
          onClick={() => {
            openDetail(a)
            onClose()
          }}
        >
          View full details →
        </button>
      </aside>
    </>
  )
}
