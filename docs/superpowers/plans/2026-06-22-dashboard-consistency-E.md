# Dashboard Consistency (sub-project E) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove dashboard drift and a misleading visual — accurate cross-domain reuse graph (#7), Summary-sourced KPIs (#10), posture caption/golden tidy (#8), and root-cause the post-rescore client-refresh staleness.

**Architecture:** Frontend-only (one optional Go golden assertion). Rebuild `crossDomainReuseGraph` from the Report's real reuse groups; source the Overview KPIs from `Summary`; fix the posture caption + pin the Rating in the golden; investigate + fix-or-document the open-view refresh.

**Tech Stack:** React 18 + TS (`web/src/insights.ts`, `web/src/components/{Dashboard,Insights}.tsx`, `web/src/accountsData.tsx`); pure-logic vitest.

**Spec:** `docs/superpowers/specs/2026-06-22-dashboard-consistency-design.md`

**Branch discipline (every task):** confirm `git branch --show-current` == `feature/dashboard-consistency-E`; NEVER `git checkout`/`git switch`. Web rule: NEVER `npm install`/`npm ci`; use `npx tsc --noEmit` / `npx vitest run` only. styleguard bans literal inline spacing styles in `.tsx`. No `--no-verify`.

---

## File Structure

- **Modify** `web/src/insights.ts` — rebuild `crossDomainReuseGraph(report, accts)`; add `kpiCounts(summary, accounts)`.
- **Modify** `web/src/insights.test.ts` — real-reuse-group edge tests; `kpiCounts` tests; extend the posture golden to assert Rating.
- **Modify** `web/src/components/Insights.tsx` — accept + pass the Report to the graph.
- **Modify** `web/src/components/Dashboard.tsx` — render `<Insights report={report} />`; Summary-sourced KPIs (#10); posture caption (#8).
- **Investigate/Modify** the drawer-owning component(s) — the refresh fix (Task 4), if a clean minimal fix exists.
- **Possibly Modify** `internal/model/model_test.go` — assert Rating in `TestPostureScoreGolden`.

---

## Task 1: #7 — Cross-domain reuse graph from real reuse groups

**Files:**
- Modify: `web/src/insights.ts` (`crossDomainReuseGraph` ~line 377; `GraphNode`/`GraphEdge` types ~371)
- Modify: `web/src/components/Insights.tsx` (signature + caller at line 27)
- Modify: `web/src/components/Dashboard.tsx` (render `<Insights report={report} />` at line 190)
- Test: `web/src/insights.test.ts`

- [ ] **Step 1: Write the failing pure-logic test** — real reuse-group edges, no fabrication.

```ts
// web/src/insights.test.ts
import { crossDomainReuseGraph } from "./insights"
import type { Report, ReuseGroup, Account } from "./api"

const grp = (size: number, domains: string[], cracked = true): ReuseGroup =>
  ({ group_id: 1, size, cracked, has_da_pathway: false, members: domains.map((d, i) => ({ username: `u${i}`, domain: d } as any)) } as ReuseGroup)
const rep = (cracked: ReuseGroup[], uncracked: ReuseGroup[] = []): Report =>
  ({ cracked_reuse: cracked, uncracked_reuse: uncracked } as Report)
const acct = (domain: string): Account => ({ domain, risk_level: "Low", cracked: true } as Account)

describe("crossDomainReuseGraph (real reuse groups)", () => {
  it("links exactly the domains that co-occur in a reuse group", () => {
    const g = crossDomainReuseGraph(rep([grp(3, ["CORP", "EU"])]), [acct("CORP"), acct("EU")])
    expect(g.edges).toHaveLength(1)
    expect(new Set([g.edges[0].source, g.edges[0].target])).toEqual(new Set(["CORP", "EU"]))
    expect(g.nodes.map((n) => n.id).sort()).toEqual(["CORP", "EU"])
  })
  it("emits NO edge for a single-domain group", () => {
    const g = crossDomainReuseGraph(rep([grp(5, ["CORP", "CORP"])]), [acct("CORP")])
    expect(g.edges).toHaveLength(0)
  })
  it("does NOT fabricate an edge between domains that share no group", () => {
    // CORP and LAB each have shared accounts, but in SEPARATE single-domain groups -> no real bridge.
    const g = crossDomainReuseGraph(rep([grp(4, ["CORP", "CORP"]), grp(4, ["LAB", "LAB"])]), [acct("CORP"), acct("LAB")])
    expect(g.edges).toHaveLength(0) // the old heuristic WRONGLY linked these
  })
  it("returns empty when report is null", () => {
    expect(crossDomainReuseGraph(null, [acct("CORP")])).toEqual({ nodes: [], edges: [] })
  })
})
```

- [ ] **Step 2: Run to verify failure**

Run: `cd web && npx vitest run insights` → FAIL (signature is `(accts)` and the heuristic fabricates edges).

- [ ] **Step 3: Rebuild `crossDomainReuseGraph`.** Replace the function body (insights.ts:377) with:

```ts
// crossDomainReuseGraph: domains as nodes, edges between domains that GENUINELY share a
// credential (co-occur in a Report reuse group). Mirrors exposure.ts:crossDomainBridges --
// no fabricated links. accts is used only for node sizing/color.
export function crossDomainReuseGraph(report: Report | null, accts: Account[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  if (!report) return { nodes: [], edges: [] }
  const domainMap = new Map<string, { total: number; critical: number }>()
  for (const a of accts) {
    const d = domainMap.get(a.domain) ?? { total: 0, critical: 0 }
    d.total++
    if (a.risk_level === "Critical") d.critical++
    domainMap.set(a.domain, d)
  }
  const pairWeight = new Map<string, number>() // "A|B" (sorted) -> shared-account count across groups
  const connected = new Set<string>()
  for (const g of [...report.cracked_reuse, ...report.uncracked_reuse]) {
    const doms = [...new Set(g.members.map((m) => m.domain))].sort()
    if (doms.length < 2) continue
    for (let i = 0; i < doms.length; i++) {
      for (let j = i + 1; j < doms.length; j++) {
        const key = `${doms[i]}|${doms[j]}`
        pairWeight.set(key, (pairWeight.get(key) ?? 0) + g.size)
        connected.add(doms[i])
        connected.add(doms[j])
      }
    }
  }
  if (pairWeight.size === 0) return { nodes: [], edges: [] }
  const nodes: GraphNode[] = [...connected].map((d) => {
    const s = domainMap.get(d) ?? { total: 0, critical: 0 }
    const color = s.critical > 20 ? "#fb7185" : s.critical > 5 ? "#fbbf24" : "#22d3ee"
    return { id: d, label: d, size: 12 + Math.sqrt(s.total) * 2, color }
  })
  const edges: GraphEdge[] = [...pairWeight].map(([key, w]) => {
    const [source, target] = key.split("|")
    return { source, target, weight: Math.max(1, Math.ceil(w / 10)), label: `${w} shared` }
  })
  return { nodes, edges }
}
```
Add `Report` to the insights.ts imports from `./api` if not already imported.

- [ ] **Step 4: Thread the Report through Insights.** In `web/src/components/Insights.tsx`:
  - Change the signature to accept the report: `export function Insights({ report }: { report: Report | null }) {` (import `type Report` from `../api`).
  - Change line 27 to `const crossDomain = crossDomainReuseGraph(report, accounts)`.
  In `web/src/components/Dashboard.tsx` line 190, change `<Insights />` to `<Insights report={report} />` (the `report` state already exists at Dashboard.tsx:48).

- [ ] **Step 5: Run to verify pass**

Run: `cd web && npx tsc --noEmit && npx vitest run insights` → PASS

- [ ] **Step 6: Commit**

```bash
test "$(git branch --show-current)" = "feature/dashboard-consistency-E"
git add web/src/insights.ts web/src/insights.test.ts web/src/components/Insights.tsx web/src/components/Dashboard.tsx
git commit -m "fix(web): cross-domain reuse graph uses real reuse groups (no fabricated edges) (#7)"
```

---

## Task 2: #10 — Primary KPIs from Summary

**Files:**
- Modify: `web/src/insights.ts` (add `kpiCounts`)
- Modify: `web/src/components/Dashboard.tsx` (lines 64-67 use `kpiCounts`)
- Test: `web/src/insights.test.ts`

- [ ] **Step 1: Write the failing test.**

```ts
// web/src/insights.test.ts
import { kpiCounts } from "./insights"
import type { Summary, Account } from "./api"

describe("kpiCounts", () => {
  const accts = [
    { cracked: true, hibp_breached: true, da_domains: "CORP.LOCAL" },
    { cracked: false, hibp_breached: false, da_domains: "None" },
  ] as Account[]
  it("prefers Summary counts when present", () => {
    const s = { total_accounts: 100, cracked: 40, hibp_breached: 25, da_pathways: 7 } as Summary
    expect(kpiCounts(s, accts)).toEqual({ total: 100, cracked: 40, breached: 25, da: 7 })
  })
  it("falls back to client counts when Summary is null", () => {
    expect(kpiCounts(null, accts)).toEqual({ total: 2, cracked: 1, breached: 1, da: 1 })
  })
})
```

- [ ] **Step 2: Run to verify failure**

Run: `cd web && npx vitest run insights` → FAIL (`kpiCounts` not exported).

- [ ] **Step 3: Implement `kpiCounts`** in `web/src/insights.ts`:

```ts
import { hasDA } from "./util" // if not already imported
import type { Summary } from "./api"  // add if needed

// kpiCounts returns the four primary Overview KPIs from the authoritative Summary
// counts (matching the report/export), falling back to client-derived counts only
// while Summary is still loading (null). Kills the client-predicate-vs-Go-counter drift.
export function kpiCounts(summary: Summary | null, accounts: Account[]): { total: number; cracked: number; breached: number; da: number } {
  return {
    total: summary?.total_accounts ?? accounts.length,
    cracked: summary?.cracked ?? accounts.filter((a) => a.cracked).length,
    breached: summary?.hibp_breached ?? accounts.filter((a) => a.hibp_breached).length,
    da: summary?.da_pathways ?? accounts.filter((a) => hasDA(a.da_domains)).length,
  }
}
```
(Confirm `hasDA` lives in `web/src/util.ts` and the `Summary` field names — `total_accounts`, `cracked`, `hibp_breached`, `da_pathways` — match `web/src/api.ts`. Adjust if different.)

- [ ] **Step 4: Use it in Dashboard.** In `web/src/components/Dashboard.tsx`, replace lines 64-67:
```ts
  const { total, cracked, breached, da } = kpiCounts(summary, accounts)
  const crackPct = total ? Math.round((cracked / total) * 100) : 0
```
(Import `kpiCounts` from `../insights`. Keep the existing `crackPct` line if it already derives from total/cracked — just ensure it uses these.)

- [ ] **Step 5: Run gates + commit**

Run: `cd web && npx tsc --noEmit && npx vitest run insights` → PASS
```bash
test "$(git branch --show-current)" = "feature/dashboard-consistency-E"
git add web/src/insights.ts web/src/insights.test.ts web/src/components/Dashboard.tsx
git commit -m "fix(web): primary Overview KPIs read authoritative Summary counts (#10)"
```

---

## Task 3: #8 — Posture caption + Rating golden

**Files:**
- Modify: `web/src/components/Dashboard.tsx` (caption at line 130)
- Modify: `web/src/insights.test.ts` (extend the posture golden to assert Rating)
- Modify: `internal/model/model_test.go` (assert Rating in `TestPostureScoreGolden` — cheap Go pin)

- [ ] **Step 1: Fix the caption.** In `web/src/components/Dashboard.tsx:130`, change
  `Security health · higher is better · target ≥ 75` to align with a real band, e.g.
  `Security health · higher is better · aim for Strong (≥ 85)`. (No phantom "75".)

- [ ] **Step 2: Extend the TS posture golden to assert Rating.** Read `web/src/insights.test.ts`'s
  existing posture golden (it mirrors Go `TestPostureScoreGolden`). For each fixture, add an
  assertion on the returned `.rating` string (e.g. the first fixture's expected rating). This pins
  the Strong/Fair/Weak thresholds Go↔TS so a future change can't drift silently.

- [ ] **Step 3: (Cheap Go pin) assert Rating in `TestPostureScoreGolden`.** In
  `internal/model/model_test.go`, add an assertion on the returned `Posture.Rating` for the golden
  fixtures (read the test to see the fixtures + expected scores, then assert the matching Rating per
  the `>=85/>=70` bands).

- [ ] **Step 4: Run + commit**

Run: `cd web && npx tsc --noEmit && npx vitest run insights` → PASS
Run: `go test ./internal/model/ -run TestPostureScoreGolden -v` → PASS
```bash
test "$(git branch --show-current)" = "feature/dashboard-consistency-E"
git add web/src/components/Dashboard.tsx web/src/insights.test.ts internal/model/model_test.go
git commit -m "fix(web): posture caption aligns to a real band; pin Rating in the Go<->TS golden (#8)"
```

---

## Task 4: Post-rescore refresh — root-cause (systematic-debugging)

**REQUIRED SUB-SKILL:** Use superpowers:systematic-debugging — root-cause BEFORE any fix.

**Files:** investigation across `web/src/accountsData.tsx`, `web/src/jobs.tsx`, and the drawer-owning component(s) (e.g. `web/src/components/Accounts.tsx`, `Actionable.tsx`, `Dashboard.tsx` riskiest table, `AccountDrawer.tsx`).

- [ ] **Step 1: Reproduce + gather evidence.** Confirmed symptom (C's live test): after a rescore
  completes, an OPEN AccountDrawer shows the OLD `risk_vector` until a hard reload, though
  `/api/accounts` already returns the new value. Known facts: `AccountsProvider`'s fetch effect is
  keyed on `[activeId, dataVersion]` (accountsData.tsx:41), and `JobsProvider` calls `bumpData()` on
  rescore `done` (jobs.tsx) — so the accounts list DOES refetch. Trace WHERE the open drawer's
  `account` comes from: is it a captured Account OBJECT held in some `selected` state (stale after
  refetch), or is it re-derived from the live `accounts` by username each render?

- [ ] **Step 2: Form the root-cause hypothesis.** Likely: the drawer is opened with a snapshot
  `account` object (`setSelected(a)`), so after the accounts array refetches the open drawer keeps
  pointing at the stale object. Confirm by reading the component that renders `<AccountDrawer account={...} />`.

- [ ] **Step 3: Minimal fix OR document.** If the hypothesis holds and a clean minimal fix exists:
  store the **selected username/key** (not the object) and derive the account from the live
  `accounts` list each render, so an open drawer reflects a completed rescore. Make the SMALLEST
  change in the one owning component; do NOT refactor the data layer or change the drawer's props if
  avoidable. If the symptom is instead a benign race (drawer reopened faster than the 1.5s poll
  caught `done`, and it DOES update on the next poll), DOCUMENT that with evidence and skip the code
  change.

- [ ] **Step 4: Test.** If a fix lands, add a pure-logic test for the corrected selection-derivation
  (e.g. a helper `selectedAccount(accounts, username)` returns the live row), OR — if behavioral —
  verify live in Task 5. If documented-benign, record the evidence in the report.

- [ ] **Step 5: Commit (only if a fix landed)**

```bash
test "$(git branch --show-current)" = "feature/dashboard-consistency-E"
git add <touched files>
git commit -m "fix(web): open AccountDrawer reflects a completed rescore without a reload"
```

---

## Task 5: Whole-of-E verification

**Files:** none (verification only)

- [ ] **Step 1: Frontend gates.** `cd web && npx tsc --noEmit && npx vitest run && npm run build` → clean.
- [ ] **Step 2: Backend gates (the Go golden change).** `gofmt -l cmd internal && go build ./... && go test ./internal/model/ ./...` → green.
- [ ] **Step 3: Live (build-and-run + Playwright at `http://127.0.0.1:8443`).** Open an audit with ≥2 domains that share a credential if available (else verify the empty-state is honest):
  - Insights "Cross-domain credential reuse" graph shows edges ONLY between domains that actually share a credential — cross-check against the Exposure "bridges" panel (they must agree).
  - the Overview KPIs match the report/export counts.
  - the posture caption reads the new band text (no "75").
  - if the refresh fix landed: recalc and confirm an open drawer/accounts reflect the new data without a reload.
  - assert the console has no 4xx/error noise.
- [ ] **Step 4: Report evidence** (gate output + graph-vs-bridges agreement + KPI match). No commit; proceed to the final whole-branch review, then finishing-a-development-branch.

---

## Self-Review notes (for the controller)

- **Spec coverage:** #7 real-reuse-group graph → Task 1; #10 Summary KPIs → Task 2; #8 caption + Rating golden → Task 3; refresh root-cause → Task 4; verification → Task 5.
- **Type consistency:** `crossDomainReuseGraph(report, accts)` new signature used in Task 1 + threaded through Insights/Dashboard; `kpiCounts(summary, accounts)` defined Task 2 + used in Dashboard; both exported from insights.ts and tested.
- **Placeholder honesty:** Task 1 Step 1 casts (`as any`/`as ReuseGroup`) to build minimal fixtures — confirm the real `ReuseGroup`/`ReportAccount`/`Report`/`Summary` field names in api.ts and adjust. Task 4 is a genuine investigation (root-cause first) — the fix is conditional on the finding; don't force a code change if it's a benign race.
- **No new endpoints; styleguard (className only); never npm install.**
