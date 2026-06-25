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
// fields (level/score/exposure/impact/percentile) live in the hero tiles, not a card.
const IDENTITY_FACTS = ["Domain", "Status", "Enabled", "Coverage"]
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

          <RiskTiles a={account} />

          <WhyCallout a={account} />

          <div className="ad-cards">
            <FactCard title="Identity" rows={pickFacts(rows, IDENTITY_FACTS)} />
            <FactCard title="Password" rows={pickFacts(rows, PASSWORD_FACTS)} />
            <FactCard title="Active Directory" rows={pickFacts(rows, AD_FACTS)} />
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

function PeerRow({
  m, isLead, revealed, onReveal, onPivot,
}: {
  m: PeerRef
  isLead: boolean
  revealed: RevealMap
  onReveal: (u: string, d: string) => void
  onPivot: (c: Crumb) => void
}) {
  const key = peerKey(m.username, m.domain)
  return (
    <li className="peer-row">
      <button className="link-btn peer-name" onClick={() => onPivot({ username: m.username, domain: m.domain })}>
        {m.username}
      </button>
      <span className={`badge ${RISK_CLASS[m.risk_level] || ""}`}>{m.risk_level}</span>
      {m.has_da_path && <span className="badge badge-da">DA</span>}
      {!m.enabled && <span className="muted">disabled</span>}
      <span className="peer-spacer" />
      {isLead && m.cracked && (
        key in revealed ? (
          <code className="mono-pw">{revealed[key]}</code>
        ) : (
          <button className="reveal-btn btn-reveal" onClick={() => onReveal(m.username, m.domain)}>Reveal</button>
        )
      )}
    </li>
  )
}

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
  const daMembers = group.members.filter((m) => m.has_da_path)
  const peers = account.similar_peers ?? []
  const nothing = !group.shares_hash && peers.length === 0
  return (
    <div className="ad-cards">
      {group.shares_hash && (
        <section className="panel ad-card">
          <div className="ad-card-title">
            Password-reuse group
            <span className="ad-card-count">{group.total}</span>
          </div>
          <p className="ad-card-sub">
            {group.cracked_count} cracked · same NT hash
            {group.truncated ? ` · showing first ${group.members.length}` : ""}
          </p>
          <ul className="peer-list">
            {group.members.map((m) => (
              <PeerRow key={peerKey(m.username, m.domain)} m={m} isLead={isLead} revealed={revealed} onReveal={onReveal} onPivot={onPivot} />
            ))}
          </ul>
        </section>
      )}
      {daMembers.length > 0 && (
        <section className="panel ad-card ad-card-danger">
          <div className="ad-card-title">⚠ Shares a password with Domain Admin</div>
          <p className="ad-card-sub">Cracking this credential is equivalent to compromising:</p>
          <ul className="peer-list">
            {daMembers.map((m) => (
              <PeerRow key={`da-${peerKey(m.username, m.domain)}`} m={m} isLead={isLead} revealed={revealed} onReveal={onReveal} onPivot={onPivot} />
            ))}
          </ul>
        </section>
      )}
      {account.escalated_by_mass_reuse && group.shares_hash && (
        <section className="panel ad-card">
          <div className="ad-card-title">Mass-reuse cluster</div>
          <p className="ad-card-sub">
            {group.total + 1} accounts share this password ({group.cracked_count} cracked). Cracking one compromises all.
          </p>
        </section>
      )}
      {peers.length > 0 && (
        <section className="panel ad-card">
          <div className="ad-card-title">
            Near-duplicate passwords
            <span className="ad-card-count">{peers.length}</span>
          </div>
          <ul className="peer-list">
            {peers.map((p) => (
              <li key={`sim-${peerKey(p.username, p.domain)}`} className="peer-row">
                <button className="link-btn peer-name" onClick={() => onPivot({ username: p.username, domain: p.domain })}>
                  {p.username}
                </button>
                <span className="peer-spacer" />
                <span className="muted">{Math.round(p.score * 100)}% match</span>
              </li>
            ))}
          </ul>
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
