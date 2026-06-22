import { useEffect, type ReactNode } from "react"
import type { Account, ScoreBreakdown } from "../api"
import { RISK_CLASS, hasDA, weaknessTags } from "../util"
import { impactIsKnown, isProvisional, coverageState } from "../matrix"
import { GLOSSARY } from "../glossary"
import { weaknessSubFactors, policyViolationText } from "../drawerFactors"

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
    ["Exposure", a.exposure_score.toFixed(1)],
    [
      "Impact",
      impactIsKnown(a) ? (
        (a.impact_score as number).toFixed(1)
      ) : (
        <span className="badge-provisional" title={GLOSSARY.impact_unknown}>Unknown</span>
      ),
    ],
    ["Coverage", coverageState(a) === "full" ? "BloodHound-enriched" : "Not enriched"],
    ...(a.percentile != null ? ([["Triage percentile", `${Math.round(a.percentile * 100)}th`]] as [string, ReactNode][]) : []),
    ["Risk score", a.risk_score.toFixed(1)],
    ["Risk vector", <code className="vector">{a.risk_vector || "—"}</code>],
    ["HIBP breaches", a.hibp_breached ? a.hibp_breach_count.toLocaleString() : "—"],
    ["Complexity", a.cracked ? a.complexity : "—"],
    ["Password length", a.cracked ? a.password_length : "—"],
    ["Meets policy", a.cracked ? policyViolationText(a) : "—"],
    [
      "Weaknesses",
      !a.cracked ? "—" : weaknessTags(a).length ? <WeakCell a={a} /> : <span className="muted">none</span>,
    ],
    ...(a.cracked && a.contains_unicode ? ([["Contains Unicode", "Yes ⚠ — non-ASCII characters"]] as [string, ReactNode][]) : []),
    ["Similarity", a.cracked && (a.similarity_score ?? 0) > 0 ? `${((a.similarity_score ?? 0) * 100).toFixed(0)}% match to another password` : "—"],
    ["Shared with", a.shared_with],
    ["DA pathway", hasDA(a.da_domains) ? a.da_domains : "—"],
    ["Controlled objects", a.controlled_object_count],
    ...(a.controls_tier0 ? ([["Controls Tier-0", "Yes ⚠ — DA-equivalent asset"]] as [string, ReactNode][]) : []),
    ["Password last set", fmtAge(a.pwd_last_set)],
    ["Password never expires", a.pwd_never_expires === true ? "Yes ⚠" : a.pwd_never_expires === false ? "No" : "Unknown"],
    ["Days out of compliance", a.days_out_of_compliance ? `${a.days_out_of_compliance}d overdue` : "—"],
    ["Escalated (Shared-DA)", a.escalated_by_shared_da ? "Yes — shares hash with a DA account" : "—"],
    ["Kerberoastable (SPN)", a.has_spn === true ? "Yes ⚠ — offline crackable via TGS" : "No"],
    ["AS-REP roastable", a.dont_req_preauth === true ? "Yes ⚠ — no pre-auth required" : "No"],
    ["Enabled", a.enabled ? "Yes" : "No"],
  ]

  // v2 breakdown reads a.score_breakdown (v2 axis sub-scores). Per D2 every breakdown
  // field is omitempty, so a missing key is a legitimate 0 (never "unknown"): the v()
  // safe-accessor coalesces undefined → 0. (impact_score null is the only true Unknown
  // and is handled separately via impactIsKnown — never coalesced.)
  const bd = a.score_breakdown
  const v = (k: keyof ScoreBreakdown): number => {
    const x = bd?.[k]
    return typeof x === "number" ? x : 0
  }
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
        {(bd || isProvisional(a)) && (
          <div className="drawer-breakdown">
            <div className="drawer-section-title">Score breakdown (v2)</div>
            <div className="breakdown-grid">
              {/* Uncracked accounts DO carry a score_breakdown (engine scoreUncracked emits
                  one); its weakness sub-scores are 0 (password unknown). The Exposure card
                  still gates on `bd`, which is present for them. */}
              {bd && (
                <BreakdownCard
                  title="Exposure"
                  score={a.exposure_score.toFixed(1)}
                  factors={[
                    ["Weakness", v("weakness_score")],
                    ...weaknessSubFactors(bd).map(([label, val]) => [`· ${label}`, val] as [string, number]),
                    ["HIBP floor", v("hibp_floor")],
                    ["Cracked floor", v("cracked_floor")],
                    ["Reuse", v("reuse_bump")],
                    ["Roastable", v("roastable_bump")],
                  ]}
                />
              )}
              {/* Impact: a known impact with a breakdown gets the factor card; an Unknown
                  impact gets the Impact-Unknown panel regardless of whether bd exists, so
                  uncracked+unenriched accounts (no bd) still get the "run enrichment" call. */}
              {impactIsKnown(a) ? (
                bd && (
                  <BreakdownCard
                    title="Impact"
                    score={(a.impact_score as number).toFixed(1)}
                    factors={[
                      ["Privilege", v("privilege_sub_score")],
                      ["DA path", v("da_component")],
                      ["Domain", v("domain_modifier")],
                    ]}
                  />
                )
              ) : (
                <div className="bd-card impact-unknown-card">
                  <div className="bd-card-head">
                    <span className="bd-card-title">Impact</span>
                    <span className="badge-provisional" title={GLOSSARY.impact_unknown}>Unknown</span>
                  </div>
                  <p className="impact-unknown-note">
                    Impact Unknown — this account was not BloodHound-enriched, so its blast
                    radius can't be computed. Run enrichment to finalize the level.
                  </p>
                </div>
              )}
            </div>
            {bd?.enabled_gated && (
              <p className="bd-note">Impact was gated because the account is disabled in AD.</p>
            )}
            {a.escalated_by_shared_da && (
              <p className="bd-note">Impact forced to 10 — shares a password with a Domain-Admin account.</p>
            )}
            {a.controls_tier0 && (
              <p className="bd-note">Privilege pinned to 10 — controls a Tier-0 / DA-equivalent asset.</p>
            )}
          </div>
        )}
      </aside>
    </>
  )
}

// BreakdownCard — v2 axis sub-score card (one per axis: Exposure / Impact). Shows the
// axis score and its per-factor contributions. This is the v2 rewrite of the card #C1
// removed; it does NOT resurrect the v1 base/temporal/environmental cards.
function BreakdownCard({ title, score, factors }: { title: string; score: string; factors: [string, number][] }) {
  return (
    <div className="bd-card">
      <div className="bd-card-head">
        <span className="bd-card-title">{title}</span>
        <span className="bd-card-score">{score}</span>
      </div>
      <div className="bd-card-factors">
        {factors.map(([name, value]) => (
          <div className="bd-factor" key={name}>
            <span>{name}</span>
            <span className="mono">{value.toFixed(2)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
