# Cross-Domain Bridge Cards Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Replace the Exposure "cross-domain credential bridges" heatmap matrix with severity-tiered **bridge cards** (one card per shared-credential bridge, worst-first).

**Architecture:** Frontend only. The data already exists in `crossDomainBridges(report).clusters` (each a `BridgeCluster`, sorted DA-first then blast-radius). Drop the now-unused `matrix` from the helper, render cards instead of the table, and remove the matrix's `pairFilter` interaction. No backend/API/deps change.

**Tech Stack:** React 18 + TS + Vite; vitest (pure-logic only).

**Branch:** continue on `feature/dashboard-clarity` (this supersedes the matrix legend/list that branch added).

**Spec:** `docs/superpowers/specs/2026-06-19-bridge-cards-design.md`

**Gates:** in `web/`: `npx tsc --noEmit`, `npx vitest run`, `npm run build` (never `npm install`).

---

## Task 1: Simplify `crossDomainBridges` — drop the matrix

**Files:** `web/src/exposure.ts` (interface `CrossDomain` ~12-16, function `crossDomainBridges` 47-76); `web/src/exposure.test.ts` (the `crossDomainBridges` describe, ~47-60).

- [ ] **Step 1 — Update the test** (`web/src/exposure.test.ts`). The current test asserts on `matrix` (`expect(matrix["CORP"]["DMZ"]).toBe(2)`). Replace that assertion to check `clusters` instead (the matrix is being removed). Find the `it("matrix counts clusters per domain pair; single-domain groups excluded", ...)` block and change it to:
```ts
  it("returns cross-domain clusters, excludes single-domain groups", () => {
    // (keep the existing `rep` fixture setup above this line unchanged)
    const { clusters, domains } = crossDomainBridges(rep)
    // single-domain groups are excluded; only cross-domain bridges remain
    expect(clusters.every((c) => c.domains.length >= 2)).toBe(true)
    expect(clusters.length).toBeGreaterThan(0)
    expect(domains).toContain("CORP")
    expect(domains).toContain("DMZ")
  })
```
Read the existing `rep` fixture in that test to keep the assertions consistent with the fixture's data (it has CORP/DMZ groups). Remove any other `matrix[...]` references in the test.

- [ ] **Step 2 — Run, expect FAIL** (the test still imports the old shape or `matrix` is still returned): `(cd web && npx vitest run exposure)`. Actually it will still PASS until step 3 removes `matrix`; the point of step 1 is to stop asserting on `matrix`. Proceed.

- [ ] **Step 3 — Remove `matrix` from the helper.** In `web/src/exposure.ts`:
  - In `interface CrossDomain` (lines 12-16) remove the `matrix: Record<string, Record<string, number>>` field. Result:
```ts
export interface CrossDomain {
  clusters: BridgeCluster[]
  domains: string[]
}
```
  - In `crossDomainBridges` (47-76) remove the `matrix` declaration and the inner double `for` loop that builds it (lines ~48, 55-62). Keep the cluster build + the domain set + the sort. Result body:
```ts
export function crossDomainBridges(report: Report): CrossDomain {
  const clusters: BridgeCluster[] = []
  const domains = new Set<string>()
  for (const g of [...report.cracked_reuse, ...report.uncracked_reuse]) {
    const doms = [...new Set(g.members.map((m) => m.domain))].sort()
    if (doms.length < 2) continue
    doms.forEach((d) => domains.add(d))
    clusters.push({
      domains: doms, size: g.size, cracked: g.cracked, hasDA: g.has_da_pathway,
      hibpMax: g.hibp_breach_count, members: g.members,
    })
  }
  // DA clusters first, then by blast radius = size × distinct-domain count.
  clusters.sort(
    (x, y) =>
      (y.hasDA ? 1 : 0) - (x.hasDA ? 1 : 0) ||
      y.size * y.domains.length - x.size * x.domains.length,
  )
  return { clusters, domains: [...domains].sort() }
}
```

- [ ] **Step 4 — Run + verify** `(cd web && npx vitest run exposure && npx tsc --noEmit)`. tsc will now flag the `matrix` usages in `Exposure.tsx` (the fallback `{ matrix: {}, ... }` and `bridges.matrix[...]`) — that's expected; Task 2 fixes them. If you want a clean checkpoint, do Task 2 before committing. **Defer the commit to the end of Task 2** (they're interdependent — exposure.ts no longer compiles against the current Exposure.tsx).

---

## Task 2: Bridge cards UI + CSS

**Files:** `web/src/components/Exposure.tsx` (state 23-25, fallback 81, `shown` 85-89, the bridge block 103-196); `web/src/styles.css` (bridge-matrix rules 1140-1149; add bridge-card rules).

- [ ] **Step 1 — Remove the matrix-only state.** In `Exposure.tsx`:
  - Delete the `pairFilter` state: remove line 23 `const [pairFilter, setPairFilter] = useState<[string, string] | null>(null)`.
  - Simplify `shown` (85-89): since there's no pairFilter, the bridges are just the sorted clusters. Replace the `const shown = pairFilter ? ... : bridges.clusters` block with:
```ts
  const visibleBridges = showAllBridges ? bridges.clusters : bridges.clusters.slice(0, 10)
  const totalBridges = bridges.clusters.length
```
  (remove the now-unused `shown`/`totalBridges`/`visibleBridges` lines at 91-92 that referenced `shown`.)
  - Fix the no-report fallback (line 81): remove `matrix: {}` →
```ts
  const bridges = report ? crossDomainBridges(report) : { clusters: [] as BridgeCluster[], domains: [] as string[] }
```

- [ ] **Step 2 — Replace the matrix block with bridge cards.** Replace the whole block from line 104 (`<div className="section-label">Cross-domain credential bridges...`) through line 196 (the closing `)}` of the `bridges.domains.length < 2` ternary) with:
```tsx
      {/* ── Cross-domain credential bridges ── */}
      <div className="section-label">
        Cross-domain credential bridges<InfoTip text={GLOSSARY.bridge_matrix} />
      </div>
      {bridges.domains.length < 2 ? (
        <div className="panel">
          <div className="muted">No credentials are shared across domains.</div>
        </div>
      ) : (
        <div className="panel">
          <div className="meta-line muted">
            {totalBridges} bridge{totalBridges === 1 ? "" : "s"} — a shared password lets an
            attacker pivot between these domains. Worst first.
          </div>
          <div className="bridge-cards">
            {visibleBridges.map((c) => {
              const cid = c.domains.join("/") + "#" + bridges.clusters.indexOf(c)
              const tier = c.hasDA ? "crit" : c.cracked ? "high" : "low"
              const tierLabel = c.hasDA
                ? "⚠ Reaches Domain Admin"
                : c.cracked
                  ? "Cracked"
                  : "Uncracked — shared hash, no cleartext"
              const open = openCluster === cid
              return (
                <div key={cid} className={`bridge-card ${tier}`}>
                  <div className="bridge-card-head">
                    <div>
                      <div className="bridge-tier">{tierLabel}</div>
                      <div className="bridge-domains">{c.domains.join(" ↔ ")}</div>
                    </div>
                    <div className="bridge-count">
                      <div className="bridge-count-n">{c.size}</div>
                      <div className="bridge-count-l">accounts</div>
                    </div>
                  </div>
                  <div className="bridge-badges">
                    <span className={`badge ${c.cracked ? "high" : ""}`}>{c.cracked ? "cracked" : "uncracked"}</span>
                    {c.hibpMax > 0 && <span className="badge">HIBP {c.hibpMax.toLocaleString()}</span>}
                    <span className="badge">{c.domains.length} domains</span>
                    <button
                      className="link-btn bridge-members-btn"
                      onClick={() => setOpenCluster(open ? null : cid)}
                    >
                      {open ? "▾" : "▸"} {c.members.length} members
                    </button>
                  </div>
                  {open && (
                    <div className="bridge-members">
                      {c.members.map((m, mi) => (
                        <div key={`${m.domain}/${m.username}/${mi}`} className="member-row">
                          <span className="muted">
                            {m.username} · {m.domain} · {m.risk_level}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
          {totalBridges > 10 && (
            <button className="link-btn" onClick={() => setShowAllBridges((v) => !v)}>
              {showAllBridges ? "show fewer" : `show all ${totalBridges}`}
            </button>
          )}
        </div>
      )}
```
(Note: the HIBP-repeat note lives under the HIBP triage section below — leave that untouched.)

- [ ] **Step 3 — CSS.** In `web/src/styles.css`:
  - **Remove** the matrix rules: `.bridge-matrix` and its variants (lines ~1140-1144), `.matrix-legend` (line ~1149), and `.bridge-cluster-row` (~1148). Keep `.member-row` / `.member-row td` (still used) and the existing `.badge` classes.
  - **Add** bridge-card styles (place near the old bridge rules):
```css
.bridge-cards { display: flex; flex-direction: column; gap: 12px; }
.bridge-card { border: 1px solid var(--glass-border); border-left: 4px solid var(--faint); border-radius: 10px; padding: 14px; background: rgba(20, 29, 49, 0.5); }
.bridge-card.crit { border-color: var(--crit); border-left-color: var(--crit); background: var(--crit-bg); }
.bridge-card.high { border-left-color: var(--high); background: var(--high-bg); }
.bridge-card.low { border-left-color: var(--faint); }
.bridge-card-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
.bridge-tier { font-size: 11px; letter-spacing: 1px; font-weight: 600; color: var(--dim); }
.bridge-card.crit .bridge-tier { color: var(--crit); }
.bridge-card.high .bridge-tier { color: var(--high); }
.bridge-domains { font-weight: 600; font-size: 15px; margin-top: 5px; }
.bridge-count { text-align: right; }
.bridge-count-n { font-family: var(--mono); font-size: 24px; font-weight: 600; line-height: 1; }
.bridge-count-l { font-size: 11px; color: var(--dim); }
.bridge-badges { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
.bridge-members-btn { margin-left: auto; }
.bridge-members { margin-top: 10px; border-top: 1px solid var(--glass-border); padding-top: 8px; display: grid; gap: 3px; }
```

- [ ] **Step 4 — Verify + commit (Tasks 1+2 together).** `(cd web && npx tsc --noEmit && npx vitest run && npm run build)` — ALL green, incl. the styleguard test (NO literal inline spacing styles — the card markup uses classes only). Confirm no unused symbols (`pairFilter`, `shown`, `setPairFilter` fully removed; `BridgeCluster` still imported/used). Commit:
```
git add web/src/exposure.ts web/src/exposure.test.ts web/src/components/Exposure.tsx web/src/styles.css
git commit -m "feat(ui): replace cross-domain bridge heatmap with severity-tiered bridge cards"
```

---

## Task 3: Verify live (folded into the branch finish)

- [ ] **Step 1 — Gate + rebuild.** `(cd web && npx tsc --noEmit && npx vitest run && npm run build)`; then `bash .claude/skills/build-and-run/scripts/build.sh`.
- [ ] **Step 2 — Playwright re-verify** on the loaded instance (`:8444` or `:8443` after restart+unlock): the Exposure view shows **bridge cards** (no matrix), severity-tiered worst-first, a **3-domain bridge renders as one card** (`GHOST ↔ PHANTOM ↔ WRAITH`), badges (cracked/HIBP/N domains) show, member-expand works, top-10 + "show all" works, no console errors.
- [ ] **Step 3 — finishing-a-development-branch:** merge `feature/dashboard-clarity` → `main`, tag `v2.12.0`, rebuild + restart `:8443`. (Per the user's instruction.)

---

## Self-review
- **Spec coverage:** retire matrix+legend+list → Task 2 (replace block) + Task 1 (drop matrix from helper) + Task 2 CSS (remove matrix rules); bridge cards w/ severity tiers + domain chain + badges + expandable members + top-N → Task 2; drop pairFilter → Task 2 Step 1; empty state kept → Task 2 Step 2; HIBP-repeat note kept (untouched below). All spec items mapped.
- **Type consistency:** `CrossDomain` loses `matrix` (Task 1) → all `bridges.matrix` usages removed (Task 2); `BridgeCluster` unchanged; `visibleBridges`/`totalBridges`/`openCluster`/`showAllBridges` consistent.
- **Confirm-by-reading:** the existing `rep` fixture in exposure.test.ts (Task 1 Step 1) to keep the rewritten assertion consistent; that `member-row` CSS is retained (Task 2 Step 3).
