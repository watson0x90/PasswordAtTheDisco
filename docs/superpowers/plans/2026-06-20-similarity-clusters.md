# Password Similarity Clusters — Expand + Click-to-Explain — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Password Similarity Clusters graph expandable (large modal) and explainable (click a username → its most-similar accounts + scores), backed by new server-computed similar-peer references that carry no cleartext.

**Architecture:** The engine already computes per-domain pairwise password similarity but keeps only each account's max score; retain the real peers (redacted: username/domain/score) on `model.Account.SimilarPeers`. The frontend builds real graph edges from those peers and renders a breakdown panel + an expand modal.

**Tech Stack:** Go 1.26 stdlib (`pwanalysis.Similar` Levenshtein). React 18 + TS + Vite. Gates: `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck ./...`; in `web/` (NEVER `npm install`): `npx tsc --noEmit`, `npx vitest run` (incl. `styleguard.test.ts`), `npm run build`.

**Spec:** `docs/superpowers/specs/2026-06-20-similarity-clusters-design.md`

**Conventions that bite:**
- `styleguard.test.ts` FAILS on literal inline spacing styles in `.tsx`. CSS classes only.
- vitest is node-env: only test pure functions.
- Hooks called unconditionally above any early return.
- Similarity is **per-domain** — peers are same-domain. `SimilarPeers` must never contain a password.

---

## File Structure

- **Modify** `internal/model/model.go` — add `SimilarPeer` type + `Account.SimilarPeers` field.
- **Modify** `internal/engine/engine.go` — compute `SimilarPeers` in `processDomainWith`/`scoreCracked`.
- **Modify** `internal/engine/engine_test.go` — `TestSimilarPeers`.
- **Modify** `web/src/api.ts` — `SimilarPeer` interface + `similar_peers` on `Account`.
- **Modify** `web/src/insights.ts` — real edges in `similarityNetwork`.
- **Modify** `web/src/insights.test.ts` — edge test.
- **Modify** `web/src/components/NetworkGraph.tsx` — `onNodeClick`.
- **Create** `web/src/components/SimilarityClusters.tsx` — extracted section + modal + breakdown.
- **Modify** `web/src/components/Insights.tsx` — render `<SimilarityClusters>`.
- **Modify** `web/src/styles.css` — `.simgraph-*`, `.simbreak-*`, `.net-node`.

---

## Task 1: Backend — `SimilarPeers` on accounts

**Files:**
- Modify: `internal/model/model.go`
- Modify: `internal/engine/engine.go`
- Test: `internal/engine/engine_test.go`

**Context:** `model.Account.Redacted()` zeroes Password/NTHash/BannedWords/KeyboardPatterns; a field with no secret passes through. `engine.processDomainWith(domain, cracked, uncracked, enr)` builds `allPasswords` (this domain's cracked passwords) when `len(cracked) <= 5000`, then calls `scoreCracked(...)` per cracked account. `scoreCracked` calls `pwanalysis.Similar(pw, allPasswords)` (sorted desc, exact matches excluded, ratio ≥ 0.7) and keeps `sims[0].Score` as `simMax`. The `model.Account` struct literal it returns sets `SimilarityScore: simMax`.

- [ ] **Step 1: Write the failing test**

Add to `internal/engine/engine_test.go`:

```go
func TestSimilarPeers(t *testing.T) {
	e := newEngine()
	cracked := []secretsdump.ParsedAccount{
		{Username: "alice", Domain: "CORP", Hash: "H1", Password: "Summer2024!", Cracked: true},
		{Username: "bob", Domain: "CORP", Hash: "H2", Password: "Summer2023!", Cracked: true},   // ~0.9 to alice
		{Username: "carol", Domain: "CORP", Hash: "H3", Password: "totally-different-xyz", Cracked: true},
		{Username: "dave", Domain: "CORP", Hash: "H4", Password: "Summer2024!", Cracked: true},   // exact reuse of alice
	}
	out := e.ProcessDomainNoEnrich("CORP", cracked, nil)
	by := map[string]model.Account{}
	for _, a := range out {
		by[a.Username] = a
	}

	// alice: similar to bob (different but close); NOT dave (exact reuse) or alice (self).
	peers := by["alice"].SimilarPeers
	if len(peers) != 1 || peers[0].Username != "bob" {
		t.Fatalf("alice.SimilarPeers = %+v, want [bob]", peers)
	}
	if peers[0].Score < 0.7 {
		t.Errorf("alice->bob score = %v, want >= 0.7", peers[0].Score)
	}
	if peers[0].Domain != "CORP" {
		t.Errorf("peer domain = %q, want CORP", peers[0].Domain)
	}

	// carol: no near-duplicates.
	if len(by["carol"].SimilarPeers) != 0 {
		t.Errorf("carol.SimilarPeers = %+v, want empty", by["carol"].SimilarPeers)
	}

	// Redacted() keeps SimilarPeers (it carries no secret).
	red := by["alice"].Redacted()
	if len(red.SimilarPeers) != 1 || red.Password != "" {
		t.Errorf("redacted alice = %+v (peers should survive, password cleared)", red)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/engine/ -run TestSimilarPeers`
Expected: FAIL — `by["alice"].SimilarPeers` undefined (compile error) until the field exists.

- [ ] **Step 3: Add the model type + field**

In `internal/model/model.go`, add near the `Account` type:

```go
// SimilarPeer is another account whose cracked password is a near-duplicate of
// this account's (Levenshtein ratio). Username/Domain/Score only — never the
// password — so it is safe to expose and survives Redacted().
type SimilarPeer struct {
	Username string  `json:"username"`
	Domain   string  `json:"domain"`
	Score    float64 `json:"score"`
}
```

Add this field to the `Account` struct (next to `SimilarityScore`):

```go
	SimilarPeers []SimilarPeer `json:"similar_peers,omitempty"`
```

Do **not** modify `Redacted()` — `SimilarPeers` holds no secret and must pass through unchanged.

- [ ] **Step 4: Compute peers in the engine**

In `internal/engine/engine.go`, in `processDomainWith`, extend the similarity-setup block to also index passwords→accounts and add a peers cache:

```go
	const similarityCap = 5000
	var allPasswords []string
	pwAccounts := map[string][]model.SimilarPeer{} // password -> accounts using it (username/domain)
	if len(cracked) <= similarityCap {
		allPasswords = make([]string, 0, len(cracked))
		for _, a := range cracked {
			allPasswords = append(allPasswords, a.Password)
			pwAccounts[a.Password] = append(pwAccounts[a.Password], model.SimilarPeer{Username: a.Username, Domain: domain})
		}
	}

	analysisCache := map[string]*pwanalysis.Analysis{}
	simCache := map[string]float64{}
	peersCache := map[string][]model.SimilarPeer{}
```

Update the cracked loop to pass `pwAccounts` + `peersCache`:

```go
	for _, a := range cracked {
		out = append(out, e.scoreCracked(domain, a, pwUsers[a.Password]-1, allPasswords, pwAccounts, analysisCache, simCache, peersCache, now, enr))
	}
```

Change `scoreCracked`'s signature to accept the two new maps (add after `allPasswords`):

```go
func (e *Engine) scoreCracked(domain string, a secretsdump.ParsedAccount, sharedWith int, allPasswords []string, pwAccounts map[string][]model.SimilarPeer, analysisCache map[string]*pwanalysis.Analysis, simCache map[string]float64, peersCache map[string][]model.SimilarPeer, now time.Time, enr Enricher) model.Account {
```

Replace the existing `simMax` block with one that also builds peers (cache both by `pw`):

```go
	simMax, ok := simCache[pw]
	if !ok {
		sims := pwanalysis.Similar(pw, allPasswords)
		if len(sims) > 0 {
			simMax = sims[0].Score
		}
		simCache[pw] = simMax
		// Map the similar passwords back to the accounts using them (same domain),
		// top 5 by score. Self never appears: Similar() excludes exact matches, so
		// s.Password != pw and pwAccounts[s.Password] cannot contain this account.
		peers := make([]model.SimilarPeer, 0, 5)
		for _, s := range sims {
			for _, acct := range pwAccounts[s.Password] {
				peers = append(peers, model.SimilarPeer{Username: acct.Username, Domain: acct.Domain, Score: s.Score})
			}
			if len(peers) >= 5 {
				break
			}
		}
		if len(peers) > 5 {
			peers = peers[:5]
		}
		peersCache[pw] = peers
	}
```

In the returned `model.Account{...}` literal, add (next to `SimilarityScore: simMax,`):

```go
		SimilarPeers: peersCache[pw],
```

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./internal/engine/ -run TestSimilarPeers -v`
Expected: PASS.

- [ ] **Step 6: Full Go gate**

Run: `gofmt -l cmd internal` (empty); `go build ./... && go vet ./... && go test ./...` (all ok); `govulncheck ./...` (no vulns).

- [ ] **Step 7: Commit**

```bash
git add internal/model/model.go internal/engine/engine.go internal/engine/engine_test.go
git commit -m "feat(engine): retain per-account similar-peer refs (redacted: username/domain/score)"
```

---

## Task 2: Frontend data — `similar_peers` + real graph edges

**Files:**
- Modify: `web/src/api.ts`
- Modify: `web/src/insights.ts`
- Test: `web/src/insights.test.ts`

**Context:** `insights.ts:similarityNetwork(accts, maxNodes=60)` selects nodes = cracked accounts with `similarity_score >= 0.7` (top 60 by score) with id `${domain}/${username}`, then builds **fake** domain-chain edges. `GraphNode`/`GraphEdge` come from `./components/NetworkGraph`.

- [ ] **Step 1: Add the TS types**

In `web/src/api.ts`, add the interface (near the other small interfaces) and the field on `Account`:

```ts
export interface SimilarPeer {
  username: string
  domain: string
  score: number
}
```
On the `Account` interface, add: `similar_peers?: SimilarPeer[]`.

- [ ] **Step 2: Write the failing edge test**

Add to `web/src/insights.test.ts`:

```ts
import { similarityNetwork } from "./insights"
import type { Account } from "./api"

const sa = (username: string, domain: string, score: number, peers: { username: string; domain: string; score: number }[]): Account =>
  ({ username, domain, cracked: true, similarity_score: score, risk_level: "High", similar_peers: peers } as Account)

describe("similarityNetwork edges", () => {
  it("builds deduped edges only between nodes, from similar_peers", () => {
    const accts: Account[] = [
      sa("alice", "CORP", 0.9, [{ username: "bob", domain: "CORP", score: 0.9 }]),
      sa("bob", "CORP", 0.9, [{ username: "alice", domain: "CORP", score: 0.9 }]),
      sa("carol", "CORP", 0.8, [{ username: "ghost", domain: "OTHER", score: 0.85 }]), // peer not a node
    ]
    const { nodes, edges } = similarityNetwork(accts)
    expect(nodes.length).toBe(3)
    expect(edges.length).toBe(1) // alice<->bob once; carol's off-graph peer dropped
    expect(edges[0].weight).toBe(3) // round(0.9*3)
    expect(edges[0].label).toBe("90%")
  })
})
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd web && npx vitest run src/insights.test.ts`
Expected: FAIL (current edges are domain-chained, not peer-based; edge count/label differ).

- [ ] **Step 4: Replace the edge block in `similarityNetwork`**

In `web/src/insights.ts`, replace the edge-building block (the `byDomain` map + the consecutive-pair chain loop, ending at `return { nodes, edges }`) with real peer edges:

```ts
  // Real edges from server-computed similar peers (same-domain). Only link peers
  // that are themselves nodes; dedup undirected pairs.
  const nodeIds = new Set(nodes.map((n) => n.id))
  const edges: GraphEdge[] = []
  const seen = new Set<string>()
  for (const a of sorted) {
    const srcId = `${a.domain}/${a.username}`
    for (const p of a.similar_peers ?? []) {
      const dstId = `${p.domain}/${p.username}`
      if (!nodeIds.has(dstId) || dstId === srcId) continue
      const key = srcId < dstId ? `${srcId}|${dstId}` : `${dstId}|${srcId}`
      if (seen.has(key)) continue
      seen.add(key)
      edges.push({
        source: srcId,
        target: dstId,
        weight: Math.max(1, Math.round(p.score * 3)),
        label: `${Math.round(p.score * 100)}%`,
      })
    }
  }
  return { nodes, edges }
```

(`sorted` is the existing top-N node array; `nodes` is the existing `GraphNode[]`. Remove the now-dead `byDomain` block entirely.)

- [ ] **Step 5: Run the test + typecheck**

Run: `cd web && npx vitest run src/insights.test.ts && npx tsc --noEmit`
Expected: tests PASS; tsc clean. (Run full `npx vitest run` to confirm nothing else broke.)

- [ ] **Step 6: Commit**

```bash
git add web/src/api.ts web/src/insights.ts web/src/insights.test.ts
git commit -m "feat(web): similar_peers type + real similarityNetwork edges from peers"
```

---

## Task 3: NetworkGraph — clickable nodes

**Files:**
- Modify: `web/src/components/NetworkGraph.tsx`
- Modify: `web/src/styles.css`

- [ ] **Step 1: Add the `onNodeClick` prop**

In `web/src/components/NetworkGraph.tsx`, add to `Props`:

```ts
  onNodeClick?: (id: string) => void
```
Destructure it in the component signature: `export function NetworkGraph({ nodes: initNodes, edges, width = 500, height = 400, onNodeClick }: Props) {`.

On the node `<g>` (the one with `onMouseEnter`/`onMouseLeave`), add a class + click handler:

```tsx
            <g key={n.id} className="net-node" onMouseEnter={() => setHovered(n.id)} onMouseLeave={() => setHovered(null)} onClick={() => onNodeClick?.(n.id)}>
```

- [ ] **Step 2: Add the pointer CSS**

Append to `web/src/styles.css`:

```css
.net-node { cursor: pointer; }
```

- [ ] **Step 3: Typecheck + build**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build`
Expected: all green (the new prop is optional — existing `<NetworkGraph>` usages still compile).

- [ ] **Step 4: Commit**

```bash
git add web/src/components/NetworkGraph.tsx web/src/styles.css
git commit -m "feat(web): NetworkGraph optional onNodeClick (clickable nodes)"
```

---

## Task 4: SimilarityClusters component (expand modal + breakdown)

**Files:**
- Create: `web/src/components/SimilarityClusters.tsx`
- Modify: `web/src/components/Insights.tsx`
- Modify: `web/src/styles.css`

**Context:** `Insights.tsx` computes `const simNet = similarityNetwork(accounts)` (~line 27) and renders the "Password Similarity Clusters" `{simNet.nodes.length >= 2 && (...)}` block (~lines 122-133) with `<NetworkGraph nodes={simNet.nodes} edges={simNet.edges} height={400} />`. `NetworkGraph` is still used elsewhere in Insights (cross-domain reuse graph), so keep that import; remove `similarityNetwork` from Insights' `../insights` import and the `simNet` const. `AccountLink` (`./AccountLink`) accepts `{ username, domain, accounts? }` and opens the shared account drawer. `RISK_CLASS` is in `../util`.

- [ ] **Step 1: Create `SimilarityClusters.tsx`**

```tsx
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
                <NetworkGraph nodes={net.nodes} edges={net.edges} height={Math.round(window.innerHeight * 0.7)} onNodeClick={setSelectedId} />
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
```

- [ ] **Step 2: Wire it into Insights.tsx**

- Add `import { SimilarityClusters } from "./SimilarityClusters"`.
- Remove `similarityNetwork` from the existing `import { … } from "../insights"` line, and delete the `const simNet = similarityNetwork(accounts)` line.
- Replace the whole `{simNet.nodes.length >= 2 && ( … )}` block (the section-label + panel + `<NetworkGraph>` for similarity) with:

```tsx
      <SimilarityClusters accounts={accounts} />
```

(Leave the cross-domain reuse `<NetworkGraph>` and its `crossDomain` data untouched.)

- [ ] **Step 3: Add CSS**

Append to `web/src/styles.css`:

```css
/* Password Similarity Clusters — expand modal + breakdown */
.simgraph-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; margin-bottom: 10px; }
.simgraph-expand { flex: none; }
.simgraph-overlay {
  position: fixed;
  inset: 0;
  z-index: 180;
  background: rgba(6, 10, 20, 0.66);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 4vh 4vw;
}
.simgraph-modal {
  width: 92vw;
  height: 86vh;
  display: flex;
  flex-direction: column;
  background: var(--glass-strong);
  border: 1px solid var(--glass-border);
  border-radius: 14px;
  overflow: hidden;
  box-shadow: 0 30px 80px -30px rgba(0, 0, 0, 0.85);
}
.simgraph-modal-head { display: flex; align-items: center; justify-content: space-between; padding: 14px 18px; border-bottom: 1px solid var(--hairline); }
.simgraph-body { flex: 1; display: flex; min-height: 0; }
.simgraph-graph { flex: 1; min-width: 0; padding: 10px; overflow: hidden; }
.simgraph-side { width: 320px; flex: none; border-left: 1px solid var(--hairline); padding: 16px 18px; overflow-y: auto; }
.simbreak-empty { color: var(--faint); font-size: 13px; }
.simbreak-head { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }
.simbreak-user { font-weight: 600; }
.simbreak-label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--faint); margin-bottom: 8px; }
.simbreak-list { display: flex; flex-direction: column; gap: 6px; }
.simbreak-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.simbreak-score { font-family: var(--mono); font-size: 12px; color: var(--accent); }
.simbreak-note { margin-top: 14px; }
```

(The inline-section breakdown shares the `.simbreak-*` classes; when not expanded it renders directly under the graph inside the panel — add `.panel > .simbreak { margin-top: 14px; }` if it needs top spacing.)

- [ ] **Step 4: Typecheck, test, build**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build`
Expected: all green (incl. styleguard — no inline styles; confirm `similarityNetwork` is no longer imported in Insights and `simNet` is gone, so no unused-symbol errors).

- [ ] **Step 5: Commit**

```bash
git add web/src/components/SimilarityClusters.tsx web/src/components/Insights.tsx web/src/styles.css
git commit -m "feat(web): similarity clusters — expand modal + click-to-explain breakdown"
```

---

## Task 5: Full gate + live verification + finish

**Files:** none (verification + release)

- [ ] **Step 1: Full gates**

```bash
cd /c/base/dev/PasswordAtTheDisco
gofmt -l cmd internal                                    # empty
go build ./... && go vet ./... && go test ./...           # all ok
govulncheck ./...                                         # No vulnerabilities found.
( cd web && npx tsc --noEmit && npx vitest run && npm run build )   # all green incl. styleguard
```

- [ ] **Step 2: Rebuild embedded binary + restart on :8443**

Stop the running patd first (binary lock), then `bash .claude/skills/build-and-run/scripts/build.sh`, then restart via PowerShell `& .claude\skills\build-and-run\scripts\restart.ps1`; confirm the version stamp matches the new commit.

**Note:** `SimilarPeers` only populates on (re-)scoring. The existing BHE Large Sample audit was scored before this change, so its accounts have **no** `similar_peers` yet — the graph will show nodes but no edges and the breakdown will say "No close matches recorded." To verify the feature end-to-end, re-apply the sample's cracks (which triggers a rescore) or re-load the sample via `tools/load_sample.sh`. Confirm which the env has and rescore so peers populate.

- [ ] **Step 3: Live Playwright verification**

Login (`watson`/`discotime`), unlock (`disco-vault-2026`), open **Overview**, scroll to Password Similarity Clusters (after rescoring so peers exist):
- Click a node → the inline breakdown lists peer accounts + scores; a peer row opens the account drawer.
- Click **Expand ⤢** → the modal opens with a large graph + side breakdown; clicking a node fills the side panel; Esc and backdrop click close it.
- Confirm edges now connect actually-similar accounts (hover shows the % label).
- Assert the browser console has no 4xx/error noise.

- [ ] **Step 4: Finish the branch**

Use **superpowers:finishing-a-development-branch**: verify tests pass, merge to `main`, tag **v2.16.0**, rebuild + restart on :8443. (Pushing stays deferred per the user's standing preference unless they say otherwise.)

---

## Self-Review notes (for the controller)

- **Spec coverage:** model+engine peers + redaction-safe + test (T1); `similar_peers` type + real edges + test (T2); clickable nodes (T3); extracted component + expand modal + breakdown + Insights wiring (T4); gate+Playwright+v2.16.0 (T5). ✓
- **Type consistency:** Go `SimilarPeer{Username,Domain,Score}` ↔ TS `SimilarPeer{username,domain,score}`; `Account.SimilarPeers`/`similar_peers`; `similarityNetwork` node id `${domain}/${username}` matches the breakdown's `accounts.find` key and the edge ids; `onNodeClick(id)` passes that same id. ✓
- **Security:** `SimilarPeers` carries no password (T1 asserts; Redacted keeps it); breakdown shows peers + scores only. ✓
- **Known operational note (T5):** peers populate only on rescore — the controller must rescore the sample audit before the live check, else the graph shows no edges (correct, not a bug).
