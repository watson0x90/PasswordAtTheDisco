import { useEffect, useMemo, useState } from "react"
import type { Account } from "../api"
import { RISK_CLASS } from "../util"
import { similarityNetwork } from "../insights"
import { NetworkGraph } from "./NetworkGraph"
import { AccountLink } from "./AccountLink"

export function SimilarityClusters({ accounts }: { accounts: Account[] }) {
  const net = useMemo(() => similarityNetwork(accounts), [accounts])
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

  if (net.nodes.length < 2) return null

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
        <NetworkGraph nodes={net.nodes} edges={net.edges} height={400} onNodeClick={setSelectedId} />
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
                <NetworkGraph nodes={net.nodes} edges={net.edges} height={modalH} onNodeClick={setSelectedId} />
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
      <div className="simbreak-label">Most similar passwords in this audit</div>
      {peers.length === 0 ? (
        <div className="muted fs-12">No close matches recorded for this account.</div>
      ) : (
        <div className="simbreak-list">
          {peers.map((p, i) => (
            <div className="simbreak-row" key={`${p.domain}/${p.username}/${i}`}>
              <AccountLink username={p.username} domain={p.domain} accounts={accounts} />
              <span className="simbreak-score">{Math.round(p.score * 100)}%</span>
            </div>
          ))}
        </div>
      )}
      <p className="muted fs-12 simbreak-note">
        Near-duplicate passwords — cracking one likely cracks the others. Passwords are never shown.
      </p>
    </div>
  )
}
