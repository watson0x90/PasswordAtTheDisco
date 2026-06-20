# Password Similarity Clusters — Expand + Click-to-Explain — Design

**Date:** 2026-06-20
**Topic:** Make the Overview "Password Similarity Clusters" network graph (a) expandable into a large modal view, and (b) explainable — clicking a username opens a breakdown naming the *most similar accounts* and their similarity scores. Backed by new server-computed similar-peer references (no cleartext). Target release **v2.16.0**.

## Problem

The similarity cluster graph shows cracked accounts with near-duplicate passwords, but:
- It's small (fixed 400px) and there's no way to see it larger.
- Nodes aren't clickable and offer no explanation of *why* an account is in the cluster or *which* accounts its password resembles.
- Its edges are a **heuristic approximation** — `insights.ts:similarityNetwork` admits "We don't have pair-level similarity data in the API (just the max score per account)" and fakes edges by chaining same-domain nodes. The backend (`engine.scoreCracked` → `pwanalysis.Similar`) computes the real pairwise similarities but discards everything except each account's single max `similarity_score`.

## Decision

Retain the real similarity peers server-side (redacted: peer username/domain + score, **never** the password) and use them to power both a meaningful click-breakdown and real graph edges. Add an Expand button that opens a large modal with the graph plus a breakdown side-panel. Approved via brainstorming.

**Key constraint (verified in code):** similarity is computed **per-domain** — `processDomainWith(domain, cracked, …)` compares each password only against other passwords *in the same domain*. So peers are same-domain; the breakdown names same-domain accounts. (Today's domain-clustered edges are therefore roughly right in spirit; we make them real pairwise links.)

**Out of scope:** cross-domain similarity (would require changing the per-domain compute model); showing any password or character-level diff (cleartext stays behind the lead-gated reveal); changing the similarity threshold (stays ≥ 0.7) or the node cap (stays 60).

## A. Backend — similar-peer references

### `internal/model/model.go`
Add the type and field:
```go
// SimilarPeer is another account whose (cracked) password is a near-duplicate of
// this account's, by Levenshtein ratio. Username/Domain/Score only — never the
// password — so it is safe to expose and survives Redacted().
type SimilarPeer struct {
	Username string  `json:"username"`
	Domain   string  `json:"domain"`
	Score    float64 `json:"score"` // 0-1, Levenshtein ratio
}
```
On `Account`, add: `SimilarPeers []SimilarPeer `json:"similar_peers,omitempty"``. `Redacted()` is unchanged — it zeroes Password/NTHash/BannedWords/KeyboardPatterns; `SimilarPeers` holds no secret, so it passes through (confirm: do NOT add it to the fields Redacted() clears).

### `internal/engine/engine.go`
In `processDomainWith`, when similarity runs (`len(cracked) <= similarityCap`, `allPasswords` built), also build a per-domain password→accounts index so similar passwords can be mapped back to accounts:
```go
pwAccounts := map[string][]model.SimilarPeer{} // password -> the accounts using it (username/domain)
for _, a := range cracked {
	pwAccounts[a.Password] = append(pwAccounts[a.Password], model.SimilarPeer{Username: a.Username, Domain: domain})
}
```
Pass `pwAccounts` into `scoreCracked` (alongside `allPasswords`). In `scoreCracked`, after the existing `pwanalysis.Similar(pw, allPasswords)` call, build the peer list (cache by `pw`, like `simCache`):
- For each `sim` in `pwanalysis.Similar(pw, allPasswords)` (already sorted by score desc, exact matches excluded, ≥ 0.7), look up `pwAccounts[sim.Password]` and append each as a `SimilarPeer{Username, Domain, Score: sim.Score}`, **excluding the account itself** (same username+domain).
- Sort by `Score` desc (stable), cap to **top 5**, assign to the account's `SimilarPeers`.
- Cache the computed `[]SimilarPeer` by `pw` in a `peersCache map[string][]model.SimilarPeer` (note: peers are the same for any account sharing `pw` except self-exclusion; do the self-exclusion after the cache lookup, or key the cache by `pw` and filter self per account — filtering per account is correct and cheap).
- When similarity is skipped (large domain, `allPasswords == nil`), `SimilarPeers` stays nil (the field omits via `omitempty`).

`scoreCracked`'s signature gains the `pwAccounts` map; update its one other caller path (`rescoreWith` → `processDomainWith` already provides it). `Rescore` reconstructs `ParsedAccount` from stored accounts (Password present), so peers recompute on re-score too.

### Test (`internal/engine/engine_test.go` or `model`)
Seed a domain with: `alice`="Summer2024!", `bob`="Summer2023!" (similar, ~0.9), `carol`="totally-different-xyz", and `dave`="Summer2024!" (exact reuse of alice). Assert: `alice.SimilarPeers` contains `bob` with score ≈ 0.9 and does **not** contain `dave` (exact match excluded) or `alice` (self); `carol.SimilarPeers` is empty; no `SimilarPeers` entry contains a password string. Confirm the redacted account still carries `SimilarPeers` (no password) after `Redacted()`.

## B. Frontend graph data + click

### `web/src/api.ts`
```ts
export interface SimilarPeer { username: string; domain: string; score: number }
```
Add `similar_peers?: SimilarPeer[]` to the `Account` interface.

### `web/src/insights.ts` — `similarityNetwork`
Keep the node selection (cracked + `similarity_score >= 0.7`, top 60 by score). Replace the domain-chain edge block with **real** edges from `similar_peers`:
- Build a `Set` of node ids (`${domain}/${username}`).
- For each node account, for each `peer` in `account.similar_peers ?? []`, compute `peerId = ${peer.domain}/${peer.username}`; if `peerId` is in the node set, add an edge `{ source: nodeId, target: peerId, weight: Math.max(1, Math.round(peer.score * 3)), label: ${Math.round(peer.score*100)}% }`.
- **Dedup** undirected edges: track a `Set` of `[min,max].join("|")` so a↔b is added once.
- If no `similar_peers` data exists on any account (older data), the graph simply has no edges (nodes still render) — acceptable; a re-score/re-ingest populates peers.

Unit-test (`web/src/insights.test.ts` if present, else add): given accounts with `similar_peers`, `similarityNetwork` returns deduped edges only between nodes in the set, with the right weight/label, and none for peers outside the node set.

### `web/src/components/NetworkGraph.tsx`
Add optional `onNodeClick?: (id: string) => void` to `Props`. On the node `<g>`, add `onClick={() => onNodeClick?.(n.id)}` and `style`-free pointer affordance via a CSS class (e.g. add `className="net-node"` to the `<g>` and a `.net-node { cursor: pointer }` rule — no inline styles, styleguard-safe). Panning is on the `<svg>` background, so a node click doesn't conflict. No behavior change when `onNodeClick` is undefined.

## C. New component — `web/src/components/SimilarityClusters.tsx`

Extract the existing "Password Similarity Clusters" block out of `Insights.tsx` into this component (Insights renders `<SimilarityClusters accounts={accounts} />`). It owns:

- **Data:** `const net = useMemo(() => similarityNetwork(accounts), [accounts])`; render only when `net.nodes.length >= 2` (current guard).
- **State:** `expanded: boolean`, `selectedId: string | null`.
- **Inline view:** the section label + intro paragraph (unchanged copy), an **"Expand ⤢"** button (class `btn`), and the inline `<NetworkGraph nodes edges height={400} onNodeClick={setSelectedId} />`. When `selectedId` is set (and not expanded), render the `<SimilarityBreakdown>` below the graph.
- **Expanded modal:** when `expanded`, render a modal overlay (`.simgraph-overlay` backdrop, `.simgraph-modal` panel) containing a header (title + close ✕), the large `<NetworkGraph nodes edges height={Math.round(window.innerHeight*0.7)} onNodeClick={setSelectedId} />` on the left, and `<SimilarityBreakdown>` as a right side-panel. `Esc` (window keydown) and backdrop click close it (`setExpanded(false)`); clicking inside the modal stops propagation.
- Mounting note: `SimilarityClusters` is rendered inside the Dashboard/Insights tree, which is within `AccountsProvider` + `AccountDrawerProvider`, so the breakdown can use `useAccountDrawer()` and `AccountLink`.

### `SimilarityBreakdown` (in the same file)
Props: `{ accounts: Account[]; selectedId: string | null }`. Resolves the selected account by id (`${domain}/${username}`). When none selected: a hint ("Click an account in the graph to see its closest password matches."). When selected:
- Header: the account's `username` (or `username@domain`) + a risk badge (`RISK_CLASS[risk_level]`).
- **"Most similar passwords in this audit"** — list `account.similar_peers` (already sorted desc, top 5) as rows: `<AccountLink username={p.username} domain={p.domain} />` + `{Math.round(p.score*100)}%`. If a peer isn't in the active account set, `AccountLink` already falls back to plain text. If `similar_peers` is empty/absent: "No close matches recorded for this account."
- A muted note: "Near-duplicate passwords — cracking one likely cracks the others. Passwords are never shown."
- (Optional) the existing account drawer is still reachable because the header username can be an `AccountLink` too.

### CSS — `web/src/styles.css`
Add class-based rules (no inline spacing — styleguard): `.simgraph-overlay` (fixed, inset 0, dim backdrop, fl/center, high z-index), `.simgraph-modal` (large panel, ~92vw × ~86vh, flex row, glass-strong bg, radius, hidden overflow), `.simgraph-modal-head` (title + close), `.simgraph-body` (flex row: graph area flex:1 + `.simgraph-side` fixed ~320px, scroll), `.simbreak-*` (header/list/row/note), `.net-node { cursor: pointer }`, and a small `.simgraph-expand` placement. Reuse existing tokens/vars.

## Data flow
`engine` computes per-domain `SimilarPeers` (redacted-safe) → stored on each account → `/api/accounts` (redacted, now includes `similar_peers`) → `useAccountsData()` → `similarityNetwork` builds nodes + **real** edges → `NetworkGraph` (clickable) → `onNodeClick` sets `selectedId` → `SimilarityBreakdown` reads `account.similar_peers` and renders peers as `AccountLink`s. Expand toggles the modal that hosts the large graph + the same breakdown.

## Security / redaction
`SimilarPeers` contains only username/domain/score — no password, no hash. It is part of the redacted `/api/accounts` payload (same trust level as the rest of the redacted account). The graph and breakdown never show cleartext; the only way to a cleartext password remains the lead-gated, audit-logged reveal in the account drawer. No new endpoint, no new secret surface.

## Testing
- **Go:** engine `SimilarPeers` test (peers + scores correct, exact-reuse and self excluded, no password); `Redacted()` keeps `SimilarPeers`. `gofmt`, `go build/vet/test`, `govulncheck`.
- **Web:** `similarityNetwork` real-edge unit test (dedup, node-set filter, weight/label). The modal + breakdown are presentational — `tsc` + `vitest` (incl. styleguard) + `npm run build`.
- **Live Playwright:** on Overview, the cluster section shows; Expand opens the modal with the large graph; clicking a node fills the breakdown with peer rows + scores; a peer row opens the account drawer; Esc/backdrop closes; no console 4xx/errors. (The BHE Large Sample audit has similarity clusters.)

## Out of scope
- Cross-domain similarity; character-level diffs or any password display.
- Persisting which nodes are expanded; graph layout changes beyond size.
- Backfilling peers without a re-score (peers populate on next ingest/apply-cracks/rescore; existing stored audits show nodes without edges until re-scored — acceptable, noted in the UI as no edges rather than an error).
