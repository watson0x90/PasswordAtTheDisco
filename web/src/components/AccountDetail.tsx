import { useEffect, useState, type ReactNode } from "react"
import { api, ApiError, type Account, type PeerRef, type Relationships } from "../api"
import { useAccountsData } from "../accountsData"
import { useAuth } from "../auth"
import { type Crumb } from "../trail"
import { accountFactRows, BreakdownCards, RiskTiles, WhyCallout, pickFacts } from "./accountFacts"
import { RISK_CLASS } from "../util"

type RevealMap = Record<string, string>
const peerKey = (u: string, d: string) => `${u}@${d}`

// Fact groups for the detail page. Labels match accountFactRows() so values render
// identically to the drawer; we just partition them into themed cards. Risk-summary
// fields (level/score/exposure/impact/percentile) live in the hero tiles, and
// identity (domain/status/enabled/coverage) lives in the hero meta line — neither is
// repeated as a card.
const PASSWORD_FACTS = [
  "Complexity", "Password length", "Meets policy", "Weaknesses",
  "Contains Unicode", "Similarity", "HIBP breaches", "Shared with",
]
const AD_FACTS = [
  "DA pathway", "Controlled objects", "Controls Tier-0", "Password last set",
  "Password never expires", "Days out of compliance", "Kerberoastable (SPN)",
  "AS-REP roastable", "Escalated (Shared-DA)", "Escalated (Mass-reuse)", "Latent risk",
]

export function AccountDetail({
  trail, onBack, onJump, onPivot, onClose,
}: {
  trail: Crumb[]
  onBack: () => void
  onJump: (index: number) => void
  onPivot: (c: Crumb) => void
  onClose: () => void
}) {
  const tail = trail[trail.length - 1]
  const { accounts } = useAccountsData()
  const { me } = useAuth()
  const isLead = me?.role === "lead"
  const account = (accounts ?? []).find((a) => a.username === tail.username && a.domain === tail.domain)

  const [rel, setRel] = useState<Relationships | null>(null)
  const [relErr, setRelErr] = useState("")
  const [revealed, setRevealed] = useState<RevealMap>({})
  const [revealErr, setRevealErr] = useState("")

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose()
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [onClose])

  useEffect(() => {
    let alive = true
    setRel(null)
    setRelErr("")
    setRevealed({})
    setRevealErr("")
    api
      .relationships(tail.username, tail.domain)
      .then((r) => alive && setRel(r))
      .catch((e) => alive && setRelErr(e instanceof ApiError ? e.message : "failed to load relationships"))
    return () => {
      alive = false
    }
  }, [tail.username, tail.domain])

  async function reveal(username: string, domain: string) {
    setRevealErr("")
    try {
      const r = await api.revealSecret(username, domain)
      setRevealed((p) => ({ ...p, [peerKey(username, domain)]: r.password }))
    } catch (e) {
      setRevealErr(e instanceof ApiError ? `reveal failed: ${e.message}` : "reveal failed")
    }
  }

  const rows = account ? accountFactRows(account) : []

  return (
    <div className="detail-overlay" role="dialog" aria-modal="true" aria-label={`Account ${tail.username}`}>
      <div className="detail-head">
        <nav className="detail-crumbs" aria-label="pivot trail">
          <span className="crumb-root">Accounts</span>
          {trail.map((c, i) => (
            <span key={peerKey(c.username, c.domain)} className="crumb-wrap">
              <span className="crumb-sep">›</span>
              {i === trail.length - 1 ? (
                <span className="crumb-current">{c.username}</span>
              ) : (
                <button className="link-btn crumb-link" onClick={() => onJump(i)}>{c.username}</button>
              )}
            </span>
          ))}
        </nav>
        <div className="detail-head-actions">
          {trail.length > 1 && <button className="link-btn" onClick={onBack}>← Back</button>}
          <button className="link-btn" onClick={onClose}>close</button>
        </div>
      </div>

      {!account ? (
        <div className="detail-body">
          <p className="muted">This account isn't in the current audit's loaded data.</p>
        </div>
      ) : (
        <div className="detail-body">
          <header className="ad-hero">
            <div className="ad-hero-id">
              <div className="ad-hero-name">
                <span className="ad-hero-user">{account.username}</span>
                <span className={`badge ${RISK_CLASS[account.risk_level] || ""}`}>{account.risk_level}</span>
              </div>
              <div className="ad-hero-meta">
                <span>{account.domain}</span>
                <span className="dot">·</span>
                <span>{account.cracked ? "Cracked" : "Uncracked"}</span>
                <span className="dot">·</span>
                <span>{account.enabled ? "Enabled" : "Disabled"}</span>
                <span className="dot">·</span>
                <span>{account.coverage === "full" ? "BloodHound-enriched" : "Not enriched"}</span>
              </div>
            </div>
            <RevealControl
              username={account.username}
              domain={account.domain}
              cracked={account.cracked}
              isLead={isLead}
              revealed={revealed}
              onReveal={reveal}
            />
          </header>

          <WhyCallout a={account} />

          <RiskTiles a={account} />

          <div className="ad-cards">
            <FactCard title="Password" rows={pickFacts(rows, PASSWORD_FACTS)} />
            <ADCard account={account} rows={pickFacts(rows, AD_FACTS)} />
            <section className="panel ad-card ad-span">
              <div className="ad-card-title">Scoring</div>
              <div className="ad-vector">
                <span className="ad-vector-label">Risk vector</span>
                <code className="vector">{account.risk_vector || "—"}</code>
              </div>
              <BreakdownCards a={account} />
            </section>
          </div>

          <RelationshipSections
            account={account}
            rel={rel}
            relErr={relErr}
            isLead={isLead}
            revealed={revealed}
            onReveal={reveal}
            onPivot={onPivot}
          />
          {revealErr && <div className="error">{revealErr}</div>}
        </div>
      )}
    </div>
  )
}

function FactCard({ title, rows }: { title: string; rows: [string, ReactNode][] }) {
  if (!rows.length) return null
  return (
    <section className="panel ad-card">
      <div className="ad-card-title">{title}</div>
      <dl className="ad-facts">
        {rows.map(([k, v]) => (
          <div className="ad-fact" key={k}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
    </section>
  )
}

// isLowSignal flags the default/empty values BloodHound enrichment would populate
// (no privilege count, no PwdLastSet, not roastable). Plain "Yes …" flags and real
// numbers are notable and never filtered.
function isLowSignal(v: ReactNode): boolean {
  if (typeof v === "number") return v === 0
  if (typeof v !== "string") return false
  const s = v.trim()
  return s === "Unknown" || s === "No" || s === "0" || s === "—"
}

// ADCard is the Active Directory card. When the account has no BloodHound coverage its
// AD attributes are all Unknown/No/0, so we show a "run enrichment" hint and hide that
// noise — but still surface any genuinely-set flag (a confirmed roastable, escalation,
// or DA path). Once enriched, every value is shown honestly.
function ADCard({ account, rows }: { account: Account; rows: [string, ReactNode][] }) {
  const enriched = account.coverage === "full"
  const shown = enriched ? rows : rows.filter(([, v]) => !isLowSignal(v))
  return (
    <section className="panel ad-card">
      <div className="ad-card-title">Active Directory</div>
      {!enriched && (
        <p className="ad-card-sub">Not BloodHound-enriched — run enrichment for privileges, password age &amp; expiry.</p>
      )}
      {shown.length > 0 && (
        <dl className="ad-facts">
          {shown.map(([k, v]) => (
            <div className="ad-fact" key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
      )}
    </section>
  )
}

// RevealControl renders the lead-only cleartext reveal for the focused account.
function RevealControl({
  username, domain, cracked, isLead, revealed, onReveal,
}: {
  username: string
  domain: string
  cracked: boolean
  isLead: boolean
  revealed: RevealMap
  onReveal: (u: string, d: string) => void
}) {
  if (!isLead || !cracked) return null
  const key = peerKey(username, domain)
  return key in revealed ? (
    <code className="mono-pw ad-hero-pw">{revealed[key]}</code>
  ) : (
    <button className="reveal-btn btn-reveal ad-hero-reveal" onClick={() => onReveal(username, domain)}>Reveal password</button>
  )
}

// PeerCells renders one table row for a reuse-group peer: account (pivot link), risk,
// DA/Tier-0 flags, status, and the lead-only per-row reveal.
function PeerCells({
  m, isLead, revealed, onReveal, onPivot,
}: {
  m: PeerRef
  isLead: boolean
  revealed: RevealMap
  onReveal: (u: string, d: string) => void
  onPivot: (c: Crumb) => void
}) {
  const key = peerKey(m.username, m.domain)
  const privileged = m.has_da_path || m.controls_tier0
  return (
    <tr className={privileged ? "rt-darow" : undefined}>
      <td className="rt-acct">
        <button className="link-btn" onClick={() => onPivot({ username: m.username, domain: m.domain })}>{m.username}</button>
      </td>
      <td><span className={`badge ${RISK_CLASS[m.risk_level] || ""}`}>{m.risk_level}</span></td>
      <td>
        {m.has_da_path && <span className="badge badge-da">DA</span>}
        {m.controls_tier0 && <span className="badge badge-t0">Tier-0</span>}
        {!privileged && <span className="muted">—</span>}
      </td>
      <td>{m.enabled ? <span className="muted">enabled</span> : <span className="rt-disabled">disabled</span>}</td>
      <td className="rt-pw">
        {isLead && m.cracked ? (
          key in revealed ? (
            <code className="mono-pw">{revealed[key]}</code>
          ) : (
            <button className="reveal-btn btn-reveal" onClick={() => onReveal(m.username, m.domain)}>Reveal</button>
          )
        ) : (
          <span className="muted">—</span>
        )}
      </td>
    </tr>
  )
}

// RelationshipSections renders the consolidated password-reuse table (Domain-Admin /
// Tier-0 members pinned at the top under a sub-header, then the rest) plus a separate
// near-duplicate table. Full-width band below the fact cards.
function RelationshipSections({
  account, rel, relErr, isLead, revealed, onReveal, onPivot,
}: {
  account: Account
  rel: Relationships | null
  relErr: string
  isLead: boolean
  revealed: RevealMap
  onReveal: (u: string, d: string) => void
  onPivot: (c: Crumb) => void
}) {
  if (relErr) return <section className="panel ad-card"><div className="error">relationships: {relErr}</div></section>
  if (!rel) return <section className="panel ad-card"><div className="muted">Loading relationships…</div></section>
  const group = rel.reuse_group
  // High-blast-radius members (confirmed DA path or Tier-0 control) pin to the top.
  const privileged = group.members.filter((m) => m.has_da_path || m.controls_tier0)
  const others = group.members.filter((m) => !m.has_da_path && !m.controls_tier0)
  const peers = account.similar_peers ?? []
  const nothing = !group.shares_hash && peers.length === 0
  const cellProps = { isLead, revealed, onReveal, onPivot }

  return (
    <div className="ad-rels">
      {group.shares_hash && (
        <section className="panel ad-card ad-rel-card">
          <div className="ad-rel-head">
            <div className="ad-card-title">Password reuse <span className="ad-card-count">{group.total}</span></div>
            <p className="ad-rel-sub">
              {group.total} account{group.total === 1 ? "" : "s"} share this exact password
              {" "}({group.cracked_count} cracked · same NT hash{group.truncated ? ` · showing first ${group.members.length}` : ""}).
            </p>
            {account.escalated_by_mass_reuse && (
              <p className="ad-rel-flag">⚠ Mass-reuse — cracking any one member compromises all {group.total + 1}.</p>
            )}
          </div>
          <table className="rt-table">
            <thead>
              <tr><th>Account</th><th>Risk</th><th>DA / Tier-0</th><th>Status</th><th>Password</th></tr>
            </thead>
            <tbody>
              {privileged.length > 0 && (
                <>
                  <tr className="rt-grouphdr"><td colSpan={5}>⚠ Domain-Admin / Tier-0 in this group · {privileged.length}</td></tr>
                  {privileged.map((m) => <PeerCells key={`p-${peerKey(m.username, m.domain)}`} m={m} {...cellProps} />)}
                  {others.length > 0 && <tr className="rt-grouphdr2"><td colSpan={5}>Other reuse members · {others.length}</td></tr>}
                </>
              )}
              {others.map((m) => <PeerCells key={`o-${peerKey(m.username, m.domain)}`} m={m} {...cellProps} />)}
            </tbody>
          </table>
        </section>
      )}
      {peers.length > 0 && (
        <section className="panel ad-card ad-rel-card">
          <div className="ad-card-title">Near-duplicate passwords <span className="ad-card-count">{peers.length}</span></div>
          <table className="rt-table">
            <thead>
              <tr><th>Account</th><th>Similarity</th></tr>
            </thead>
            <tbody>
              {peers.map((p) => (
                <tr key={`sim-${peerKey(p.username, p.domain)}`}>
                  <td className="rt-acct">
                    <button className="link-btn" onClick={() => onPivot({ username: p.username, domain: p.domain })}>{p.username}</button>
                  </td>
                  <td className="muted">{Math.round(p.score * 100)}% match</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
      {nothing && (
        <section className="panel ad-card">
          <div className="ad-card-title">Relationships</div>
          <p className="ad-card-sub">No password-reuse peers or near-duplicates found for this account.</p>
        </section>
      )}
    </div>
  )
}
