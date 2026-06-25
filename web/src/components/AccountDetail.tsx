import { useEffect, useState, type ReactNode } from "react"
import { api, ApiError, type Account, type PeerRef, type Relationships } from "../api"
import { useAccountsData } from "../accountsData"
import { useAuth } from "../auth"
import { type Crumb } from "../trail"
import { accountFactRows, BreakdownCards, RiskTiles, WhyCallout, pickFacts } from "./accountFacts"
import { RISK_CLASS, hasDA, weaknessTags } from "../util"
import { disabledLatentRisk } from "../disabledRisk"

type RevealMap = Record<string, string>
const peerKey = (u: string, d: string) => `${u}@${d}`

// Fact groups for the detail page. Labels match accountFactRows() so values render
// identically to the drawer; we just partition them into themed cards. Risk-summary
// fields (level/score/exposure/impact/percentile) live in the hero tiles, and
// identity (domain/status/enabled/coverage) lives in the hero meta line — neither is
// repeated as a card.
// Neutral "details" facts shown under the risk-flag chips in each card. Labels match
// accountFactRows(); the dangerous states are surfaced as chips instead (see *Flags).
const PASSWORD_DETAILS = ["Complexity", "Password length", "Similarity", "Contains Unicode"]

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

  function hide(key: string) {
    setRevealed((p) => {
      const next = { ...p }
      delete next[key]
      return next
    })
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
          </header>

          <WhyCallout a={account} />

          <RiskTiles a={account} />

          <div className="ad-cards">
            <PasswordCard account={account} rows={rows} isLead={isLead} revealed={revealed} onReveal={reveal} onHide={hide} />
            <ADCard account={account} rows={rows} />
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

type Flag = { label: string; level: "bad" | "warn" }

// FlagChips renders the "Risk flags" band — the dangerous states of a card surfaced as
// coloured chips. Renders nothing when there are no flags.
function FlagChips({ flags }: { flags: Flag[] }) {
  if (!flags.length) return null
  return (
    <>
      <p className="ad-flags-label">Risk flags</p>
      <div className="ad-flags">
        {flags.map((f, i) => (
          <span key={i} className={`ad-chip ${f.level === "bad" ? "ad-chip-bad" : "ad-chip-warn"}`}>{f.label}</span>
        ))}
      </div>
    </>
  )
}

// DetailGrid renders the neutral measurable facts under the flags.
function DetailGrid({ rows }: { rows: [string, ReactNode][] }) {
  if (!rows.length) return null
  return (
    <>
      <p className="ad-flags-label">Details</p>
      <dl className="ad-facts">
        {rows.map(([k, v]) => (
          <div className="ad-fact" key={k}><dt>{k}</dt><dd>{v}</dd></div>
        ))}
      </dl>
    </>
  )
}

function passwordFlags(a: Account): Flag[] {
  const f: Flag[] = []
  if (a.cracked && !a.meets_policy) f.push({ label: "Fails policy", level: "bad" })
  for (const w of weaknessTags(a)) f.push({ label: w, level: "warn" })
  if (a.hibp_breached) f.push({ label: `In HIBP ×${a.hibp_breach_count.toLocaleString()}`, level: "bad" })
  if ((a.shared_with ?? 0) > 0) f.push({ label: `Reused ×${a.shared_with}`, level: "warn" })
  return f
}

function adFlags(a: Account): Flag[] {
  const f: Flag[] = []
  if (hasDA(a.da_domains)) f.push({ label: "DA pathway", level: "bad" })
  if (a.controls_tier0) f.push({ label: "Controls Tier-0", level: "bad" })
  if ((a.controlled_object_count ?? 0) > 100) f.push({ label: `Controls ${a.controlled_object_count.toLocaleString()} objects`, level: "bad" })
  if (a.has_spn) f.push({ label: "Kerberoastable", level: "bad" })
  if (a.dont_req_preauth) f.push({ label: "AS-REP roastable", level: "bad" })
  if (a.pwd_never_expires) f.push({ label: "Never expires", level: "warn" })
  if ((a.days_out_of_compliance ?? 0) > 0) f.push({ label: `${a.days_out_of_compliance}d overdue`, level: "warn" })
  if (disabledLatentRisk(a)) f.push({ label: "Disabled · PtH", level: "warn" })
  return f
}

// RevealRow is the full-width lead-only cleartext control inside the Password card:
// a "Reveal password" button → on reveal, the cleartext plus Copy and Hide actions.
function RevealRow({
  account, isLead, revealed, onReveal, onHide,
}: {
  account: Account
  isLead: boolean
  revealed: RevealMap
  onReveal: (u: string, d: string) => void
  onHide: (key: string) => void
}) {
  const [copied, setCopied] = useState(false)
  if (!isLead || !account.cracked) return null
  const key = peerKey(account.username, account.domain)
  const pw = revealed[key]
  if (pw == null) {
    return (
      <button className="ad-reveal-btn" onClick={() => onReveal(account.username, account.domain)}>Reveal password</button>
    )
  }
  function copy() {
    navigator.clipboard?.writeText(pw)
      .then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1500) })
      .catch(() => {})
  }
  return (
    <div className="ad-reveal-shown">
      <code className="mono-pw">{pw}</code>
      <div className="ad-reveal-actions">
        <button className="reveal-btn btn-reveal" onClick={copy}>{copied ? "Copied ✓" : "Copy"}</button>
        <button className="link-btn" onClick={() => onHide(key)}>Hide</button>
      </div>
    </div>
  )
}

// PasswordCard: the cleartext reveal row, then password risk flags, then neutral details.
function PasswordCard({
  account, rows, isLead, revealed, onReveal, onHide,
}: {
  account: Account
  rows: [string, ReactNode][]
  isLead: boolean
  revealed: RevealMap
  onReveal: (u: string, d: string) => void
  onHide: (key: string) => void
}) {
  return (
    <section className="panel ad-card">
      <div className="ad-card-title">Password</div>
      <RevealRow account={account} isLead={isLead} revealed={revealed} onReveal={onReveal} onHide={onHide} />
      <FlagChips flags={passwordFlags(account)} />
      <DetailGrid rows={pickFacts(rows, PASSWORD_DETAILS)} />
    </section>
  )
}

// ADCard: BloodHound-derived AD risk flags + details. Un-enriched accounts show a
// "run enrichment" hint (their AD attributes are Unknown) plus any non-enrichment flag.
function ADCard({ account, rows }: { account: Account; rows: [string, ReactNode][] }) {
  const enriched = account.coverage === "full"
  // Controlled-object count appears as a flag when high (>100); otherwise as a neutral
  // detail — never both (avoids showing e.g. "898" twice).
  const detailLabels = (account.controlled_object_count ?? 0) > 100
    ? ["Password last set"]
    : ["Controlled objects", "Password last set"]
  return (
    <section className="panel ad-card">
      <div className="ad-card-title">Active Directory</div>
      {!enriched && (
        <p className="ad-card-sub">Not BloodHound-enriched — run enrichment for privileges &amp; password age.</p>
      )}
      <FlagChips flags={adFlags(account)} />
      {enriched && <DetailGrid rows={pickFacts(rows, detailLabels)} />}
    </section>
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
