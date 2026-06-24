import { useEffect, useState } from "react"
import { api, ApiError, type Account, type PeerRef, type Relationships } from "../api"
import { useAccountsData } from "../accountsData"
import { useAuth } from "../auth"
import { type Crumb } from "../trail"
import { explainLevel } from "../whyLevel"
import { accountFactRows, BreakdownCards } from "./accountFacts"
import { RISK_CLASS } from "../util"

type RevealMap = Record<string, string>
const peerKey = (u: string, d: string) => `${u}@${d}`

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
          <div className="detail-title-row">
            <span className="detail-title">{account.username}@{account.domain}</span>
            <span className={`badge ${RISK_CLASS[account.risk_level] || ""}`}>{account.risk_level}</span>
            {isLead && account.cracked && (
              peerKey(account.username, account.domain) in revealed ? (
                <code className="mono-pw">{revealed[peerKey(account.username, account.domain)]}</code>
              ) : (
                <button className="reveal-btn btn-reveal" onClick={() => reveal(account.username, account.domain)}>Reveal</button>
              )
            )}
          </div>

          <section className="detail-why">
            <div className="detail-section-title">Why this level</div>
            {explainLevel(account).map((line, i) => (
              <p key={i} className={i === 0 ? "why-headline" : "why-detail"}>{line}</p>
            ))}
          </section>

          <section className="detail-facts">
            <dl className="drawer-fields">
              {accountFactRows(account).map(([k, v]) => (
                <div className="drawer-row" key={k}><dt>{k}</dt><dd>{v}</dd></div>
              ))}
            </dl>
          </section>

          <BreakdownCards a={account} />

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
      <button className="link-btn" onClick={() => onPivot({ username: m.username, domain: m.domain })}>
        {m.username}@{m.domain}
      </button>
      <span className={`badge ${RISK_CLASS[m.risk_level] || ""}`}>{m.risk_level}</span>
      {m.has_da_path && <span className="badge badge-da">DA</span>}
      {!m.enabled && <span className="muted">disabled</span>}
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
  if (relErr) return <div className="error">relationships: {relErr}</div>
  if (!rel) return <div className="muted">Loading relationships…</div>
  const group = rel.reuse_group
  const daMembers = group.members.filter((m) => m.has_da_path)
  const peers = account.similar_peers ?? []
  return (
    <>
      {group.shares_hash && (
        <section className="detail-rel">
          <div className="detail-section-title">Password-reuse group ({group.total})</div>
          <p className="muted">
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
        <section className="detail-rel rel-da">
          <div className="detail-section-title">⚠ Shares a password with Domain Admin</div>
          <p className="muted">Cracking this credential is equivalent to compromising:</p>
          <ul className="peer-list">
            {daMembers.map((m) => (
              <PeerRow key={`da-${peerKey(m.username, m.domain)}`} m={m} isLead={isLead} revealed={revealed} onReveal={onReveal} onPivot={onPivot} />
            ))}
          </ul>
        </section>
      )}
      {account.escalated_by_mass_reuse && group.shares_hash && (
        <section className="detail-rel">
          <div className="detail-section-title">Mass-reuse cluster</div>
          <p className="muted">
            {group.total + 1} accounts share this password ({group.cracked_count} cracked). Cracking one compromises all.
          </p>
        </section>
      )}
      {peers.length > 0 && (
        <section className="detail-rel">
          <div className="detail-section-title">Near-duplicate passwords</div>
          <ul className="peer-list">
            {peers.map((p) => (
              <li key={`sim-${peerKey(p.username, p.domain)}`} className="peer-row">
                <button className="link-btn" onClick={() => onPivot({ username: p.username, domain: p.domain })}>
                  {p.username}@{p.domain}
                </button>
                <span className="muted">{Math.round(p.score * 100)}% match</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </>
  )
}
