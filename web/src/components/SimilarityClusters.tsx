import { useEffect, useRef, useState } from "react"
import { api, ApiError, type Account } from "../api"
import { useAuth } from "../auth"
import { RISK_CLASS } from "../util"
import { NetworkGraph } from "./NetworkGraph"
import { AccountLink } from "./AccountLink"
import type { Graph } from "../metricsBundle"

// graph is required — both callers (org Dashboard and per-domain DomainDetail) pass
// bundle.reports.similarity_graph / dm.reports.similarity_graph from the Go bundle.
// accounts is still needed for the SimilarityBreakdown drill-down (node-click lookup).
export function SimilarityClusters({ accounts, graph }: { accounts: Account[]; graph: Graph }) {
  const [expanded, setExpanded] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [modalH, setModalH] = useState(() => Math.round(window.innerHeight * 0.7))
  useEffect(() => {
    function onResize() { setModalH(Math.round(window.innerHeight * 0.7)) }
    window.addEventListener("resize", onResize)
    return () => window.removeEventListener("resize", onResize)
  }, [])

  useEffect(() => {
    if (!expanded) return
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setExpanded(false)
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [expanded])

  if (graph.nodes.length < 2) return null

  const selected = selectedId ? accounts.find((a) => `${a.domain}/${a.username}` === selectedId) ?? null : null

  return (
    <>
      <div className="section-label">Password Similarity Clusters</div>
      <div className="panel">
        <div className="simgraph-head">
          <p className="muted fs-12 mb-0">
            Accounts with ≥ 70% password similarity — clustered by domain. Near-duplicate passwords are
            trivially guessable if one is compromised. Click a node to see its closest matches.
          </p>
          <button className="btn simgraph-expand" onClick={() => setExpanded(true)}>Expand ⤢</button>
        </div>
        <NetworkGraph nodes={graph.nodes} edges={graph.edges} height={400} onNodeClick={setSelectedId} />
        {!expanded && selected && <SimilarityBreakdown account={selected} accounts={accounts} />}
      </div>

      {expanded && (
        <div className="simgraph-overlay" onClick={() => setExpanded(false)}>
          <div className="simgraph-modal" onClick={(e) => e.stopPropagation()}>
            <div className="simgraph-modal-head">
              <span className="section-label mb-0">Password Similarity Clusters</span>
              <button className="net-btn" onClick={() => setExpanded(false)} title="Close">✕</button>
            </div>
            <div className="simgraph-body">
              <div className="simgraph-graph">
                <NetworkGraph nodes={graph.nodes} edges={graph.edges} height={modalH} onNodeClick={setSelectedId} />
              </div>
              <div className="simgraph-side">
                <SimilarityBreakdown account={selected} accounts={accounts} />
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

function SimilarityBreakdown({ account, accounts }: { account: Account | null; accounts: Account[] }) {
  const { me } = useAuth()
  const isLead = me?.role === "lead"
  const [revealed, setRevealed] = useState<Record<string, string>>({})
  const [revealing, setRevealing] = useState("")
  const [revealErr, setRevealErr] = useState("")
  const timers = useRef<number[]>([])
  useEffect(() => () => { timers.current.forEach(clearTimeout) }, [])

  async function reveal(username: string, domain: string) {
    const key = `${domain}/${username}`
    setRevealing(key)
    setRevealErr("")
    try {
      const r = await api.revealSecret(username, domain)
      setRevealed((prev) => ({ ...prev, [key]: r.password }))
      timers.current.push(window.setTimeout(() => hide(key), 45000))
    } catch (e) {
      setRevealErr(e instanceof ApiError ? `reveal failed: ${e.message}` : "reveal failed")
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
  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text)
    } catch {
      /* clipboard may be unavailable; ignore */
    }
  }
  function revealCell(username: string, domain: string) {
    if (!isLead) return null
    const key = `${domain}/${username}`
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
      <button className="reveal-btn" disabled={revealing === key} onClick={() => reveal(username, domain)}>
        {revealing === key ? "…" : "reveal"}
      </button>
    )
  }

  if (!account) {
    return <div className="simbreak-empty">Click an account in the graph to see its closest password matches.</div>
  }
  const peers = account.similar_peers ?? []
  return (
    <div className="simbreak">
      <div className="simbreak-head">
        <span className="simbreak-user">{account.username}</span>
        <span className="muted">{account.domain}</span>
        <span className={`badge ${RISK_CLASS[account.risk_level] || ""}`}>{account.risk_level}</span>
      </div>
      {isLead && <div className="simbreak-reveal">{revealCell(account.username, account.domain)}</div>}
      <div className="simbreak-label">Most similar passwords in this audit</div>
      {peers.length === 0 ? (
        <div className="muted fs-12">No close matches recorded for this account.</div>
      ) : (
        <div className="simbreak-list">
          {peers.map((p, i) => (
            <div className="simbreak-row" key={`${p.domain}/${p.username}/${i}`}>
              <AccountLink username={p.username} domain={p.domain} accounts={accounts} />
              <span className="simbreak-score">{Math.round(p.score * 100)}%</span>
              {revealCell(p.username, p.domain)}
            </div>
          ))}
        </div>
      )}
      {revealErr && <div className="error">{revealErr}</div>}
      <p className="muted fs-12 simbreak-note">
        Revealing a password is lead-only and recorded in the audit log — never the password itself.
      </p>
    </div>
  )
}
